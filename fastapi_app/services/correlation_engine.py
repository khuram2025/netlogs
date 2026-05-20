"""
Correlation Engine - Multi-stage event correlation for detecting complex attack patterns.

Evaluates correlation rules by querying ClickHouse for events matching each stage
in sequence, with variable substitution between stages.
"""

import asyncio
import hashlib
import json
import logging
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.clickhouse import ClickHouseClient
from ..db.database import async_session_maker
from ..models.correlation import CorrelationRule, CorrelationIncident
from ..models.alert import Alert, AlertRule
from ..core.correlation_fields import (
    DEFAULT_SOURCE,
    NON_FIELD_FILTER_KEYS,
    NUMERIC_ONLY_OPERATORS,
    SOURCE_TABLES,
    get_sample_columns,
    get_source_fields,
    parse_field_op,
    resolve_field,
)

logger = logging.getLogger(__name__)

# Duplicate-alert / match dedup window.
ALERT_DEDUP_MINUTES = 5


class StageEvalError(Exception):
    """Raised when a correlation stage cannot be evaluated safely.

    Covers an invalid filter field, an operator/type mismatch, a non-numeric
    value for a numeric field, or a required ``$stageN.field`` variable that
    could not be resolved. The engine treats any of these as a *stage failure*
    (fail-closed) rather than silently broadening or skipping the condition.
    """


def _recent_alert_cutoff(minutes: int = ALERT_DEDUP_MINUTES) -> datetime:
    """Return the UTC timestamp ``minutes`` ago.

    Replaces the old ``datetime.replace(minute=now.minute - 5)`` which raised
    ``ValueError`` during the first five minutes of every hour.
    """
    return datetime.now(timezone.utc) - timedelta(minutes=minutes)


# Maps a stage group-by field to a canonical entity type (Phase 1: IP-centric;
# Phase 4 grows this into a full entity model).
_ENTITY_TYPE_BY_FIELD = {
    "srcip": "ip",
    "dstip": "ip",
    "device_ip": "ip",
}


def _entity_type_for_field(field: Optional[str]) -> str:
    """Canonical entity type for a group-by field."""
    if not field:
        return "none"
    return _ENTITY_TYPE_BY_FIELD.get(field, field)


def match_fingerprint(rule_id: int, rule_version: int,
                      entity_type: str, entity_value: str) -> str:
    """Stable identifier for a (rule, rule-version, entity) attack chain.

    Two matches with the same fingerprint are 'the same chain'. Suppression
    keeps a discrete rule from recording the same fingerprint more than once
    per suppression window — so match counts measure distinct chains, not
    scheduler ticks.
    """
    raw = f"{rule_id}|{rule_version}|{entity_type}|{entity_value}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def _is_match_suppressed(fingerprint: str, suppress_window: int) -> bool:
    """True if a match with this fingerprint was already recorded inside the
    suppression window — used to stop a discrete rule from re-recording the
    same attack chain on every 60-second scheduler tick."""
    if not fingerprint:
        return False
    try:
        client = ClickHouseClient.get_client()
        r = client.query(
            "SELECT count() FROM correlation_matches "
            "WHERE match_fingerprint = {fp:String} "
            "AND timestamp > now() - INTERVAL {w:UInt32} SECOND",
            parameters={"fp": fingerprint, "w": int(suppress_window)},
        )
        return bool(r.result_rows) and r.result_rows[0][0] > 0
    except Exception as e:
        # Fail open on the suppression check: recording a possible duplicate
        # is safer than silently dropping a genuine new match.
        logger.error(f"Suppression check failed: {e}")
        return False


def ensure_correlation_matches_table():
    """Create the correlation_matches table in ClickHouse if it doesn't exist."""
    try:
        client = ClickHouseClient.get_client()
        client.command("""
            CREATE TABLE IF NOT EXISTS correlation_matches (
                timestamp DateTime64(3),
                rule_id UInt32,
                rule_name String,
                severity String,
                stages_matched UInt8,
                total_stages UInt8,
                stage_details String,
                key_value String,
                total_events UInt32,
                mitre_tactic String,
                mitre_technique String
            ) ENGINE = MergeTree()
            PARTITION BY toYYYYMM(timestamp)
            ORDER BY (timestamp, rule_id)
            TTL toDateTime(timestamp) + INTERVAL 6 MONTH DELETE
        """)
        logger.info("Correlation matches table ensured in ClickHouse")
    except Exception as e:
        logger.error(f"Failed to create correlation_matches table: {e}")


def _resolve_variable(value: str, variables: dict):
    """Resolve a ``$stageN.field`` reference.

    Returns (resolved_value, optional_flag). ``optional_flag`` is True when the
    reference ended with ``?`` (an explicitly optional variable). Raises
    ``StageEvalError`` when a *required* variable cannot be resolved — the
    engine must fail closed rather than drop the join condition.
    """
    ref = value[1:]
    optional = ref.endswith("?")
    if optional:
        ref = ref[:-1]

    resolved = None
    parts = ref.split(".", 1)
    if len(parts) == 2 and variables:
        stage_key, var_field = parts
        resolved = (variables.get(stage_key) or {}).get(var_field)

    if resolved is None or resolved == "":
        if optional:
            return None, True
        raise StageEvalError(
            f"Required variable '{value}' could not be resolved from a prior stage"
        )
    return resolved, optional


def _build_where_clause(filter_config: dict, variables: dict = None,
                        source: str = DEFAULT_SOURCE) -> Tuple[str, dict]:
    """Build a parameterized ClickHouse WHERE clause from a stage filter config.

    Returns ``(where_sql, params)`` where ``where_sql`` contains only
    allow-listed identifiers and ``{pN:Type}`` placeholders, and ``params`` maps
    each placeholder to its bound value. Raises ``StageEvalError`` on an
    unknown field, an operator/type mismatch, a bad numeric value, or an
    unresolved required variable (fail-closed).
    """
    fields = get_source_fields(source)
    if fields is None:
        raise StageEvalError(f"Unknown data source '{source}'")

    conditions: List[str] = []
    params: dict = {}
    idx = 0

    for key, value in (filter_config or {}).items():
        if key in NON_FIELD_FILTER_KEYS:
            continue

        actual_field, op = parse_field_op(key)
        if actual_field not in fields:
            raise StageEvalError(
                f"Field '{actual_field}' is not an allowed column for source '{source}'"
            )
        ftype = fields[actual_field]

        # Variable substitution ($stage1.srcip -> actual value), fail-closed.
        if isinstance(value, str) and value.startswith("$"):
            resolved, optional = _resolve_variable(value, variables)
            if resolved is None and optional:
                continue  # explicitly optional + unresolved -> skip condition
            value = resolved

        if op in NUMERIC_ONLY_OPERATORS and ftype != "numeric":
            raise StageEvalError(
                f"Operator '{op}' on '{actual_field}' requires a numeric field"
            )

        pname = f"p{idx}"
        idx += 1

        if ftype == "numeric":
            try:
                params[pname] = float(value)
            except (TypeError, ValueError):
                raise StageEvalError(
                    f"Filter '{key}' requires a numeric value, got {value!r}"
                )
            conditions.append(f"{actual_field} {op} {{{pname}:Float64}}")
        elif ftype == "ip":
            params[pname] = str(value)
            conditions.append(f"{actual_field} {op} toIPv4({{{pname}:String}})")
        else:  # string
            params[pname] = str(value)
            conditions.append(f"{actual_field} {op} {{{pname}:String}}")

    where = " AND ".join(conditions) if conditions else "1=1"
    return where, params


def _fetch_stage_samples(source: str, table: str, full_where: str,
                         params: dict, limit: int = 3) -> list:
    """Best-effort: fetch a few representative raw events for a matched stage,
    using that source's sample columns, as an evidence trail so an analyst can
    see *why* a stage matched without re-querying approximate logs."""
    try:
        client = ClickHouseClient.get_client()
        cols = get_sample_columns(source)
        col_sql = ", ".join(cols)
        query = (f"SELECT {col_sql} FROM {table} WHERE {full_where} "
                 f"ORDER BY timestamp DESC LIMIT {int(limit)}")
        rows = client.query(query, parameters=params).result_rows
        return [{cols[i]: str(r[i]) for i in range(len(cols))} for r in rows]
    except Exception as e:
        logger.debug(f"Stage sample fetch failed: {e}")
        return []


# Phase 2: cap on how many stage-1 candidate entities are carried forward in
# one evaluation. Bounds query cost; performance scaling (cursors / rollups)
# is a documented later concern.
MAX_CANDIDATES = 20


def _safe_int(value, label: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        raise StageEvalError(f"Invalid {label}: {value!r}")


def _as_list(value) -> list:
    """Normalise a scalar / list / None into a list."""
    if value is None or value == "":
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _stage_time_filter(window_seconds: int, anchor: Optional[datetime] = None):
    """Return (sql, params) for a stage's time predicate.

    Trailing window ending at now() when ``anchor`` is None; an anchored
    ``(anchor, anchor + window]`` window for sequence-ordered stages — this is
    what makes "stage B follows stage A" provable.
    """
    w = _safe_int(window_seconds, "window")
    if anchor is None:
        return f"timestamp > now() - INTERVAL {w} SECOND", {}
    return (
        "timestamp > {_anchor:DateTime64(3)} "
        f"AND timestamp <= {{_anchor:DateTime64(3)}} + INTERVAL {w} SECOND",
        {"_anchor": anchor},
    )


def _entity_where(entity: dict, source: str):
    """Build (sql, params) binding each join key to the entity value.

    Each key may be a canonical entity (``ip``, ``user``, ...) or a native
    column; it is resolved to *this source's* column — which is what lets a
    rule join stages across different data sources.
    """
    fields = get_source_fields(source) or {}
    conds, params = [], {}
    for i, (key, value) in enumerate(entity.items()):
        native = resolve_field(source, key)
        if native is None:
            raise StageEvalError(
                f"Join key '{key}' has no column mapping for source '{source}'")
        ftype = fields.get(native, "string")
        pn = f"e{i}"
        if ftype == "numeric":
            params[pn] = float(value)
            conds.append(f"{native} = {{{pn}:Float64}}")
        elif ftype == "ip":
            params[pn] = str(value)
            conds.append(f"{native} = toIPv4({{{pn}:String}})")
        else:
            params[pn] = str(value)
            conds.append(f"{native} = {{{pn}:String}}")
    return (" AND ".join(conds) if conds else "1=1"), params


def _stage_candidates(stage: dict, group_fields: list, variables: dict,
                      window: int, anchor: Optional[datetime] = None,
                      limit: int = MAX_CANDIDATES) -> list:
    """Evaluate a grouped stage and return every entity that meets the
    threshold as a candidate chain head:
    ``[{entity: {field: value}, count, first_event, last_event}, ...]``.
    """
    client = ClickHouseClient.get_client()
    source = stage.get("source", DEFAULT_SOURCE)
    table = SOURCE_TABLES.get(source)
    if table is None:
        raise StageEvalError(f"Unknown data source '{source}'")
    threshold = _safe_int(stage.get("threshold", 1), "threshold")

    # Resolve each join key (canonical entity or native column) to this
    # source's column; the GROUP BY uses native columns.
    native_fields = []
    for gf in group_fields:
        native = resolve_field(source, gf)
        if native is None:
            raise StageEvalError(
                f"join/group field '{gf}' is not valid for source '{source}'"
            )
        native_fields.append(native)

    where, params = _build_where_clause(stage.get("filter", {}) or {}, variables, source)
    window = _safe_int(window, "window")
    gb = ", ".join(native_fields)
    n = len(group_fields)

    # Phase 6: anomaly mode — fire when an entity's count in this window
    # exceeds (its baseline average x multiplier), not a fixed threshold.
    anomaly = stage.get("anomaly")
    if anomaly and anchor is None:
        bw = min(30, max(1, _safe_int(anomaly.get("baseline_windows", 6),
                                      "baseline_windows")))
        try:
            mult = float(anomaly.get("multiplier", 3.0) or 3.0)
        except (TypeError, ValueError):
            raise StageEvalError("anomaly multiplier must be numeric")
        min_count = _safe_int(anomaly.get("min_count", threshold), "min_count")
        total_span = window * (bw + 1)
        query = f"""
            SELECT {gb},
                   countIf(timestamp > now() - INTERVAL {window} SECOND) AS cur,
                   count() AS tot,
                   minIf(timestamp, timestamp > now() - INTERVAL {window} SECOND) AS first_ts,
                   maxIf(timestamp, timestamp > now() - INTERVAL {window} SECOND) AS last_ts
            FROM {table}
            WHERE timestamp > now() - INTERVAL {total_span} SECOND AND ({where})
            GROUP BY {gb}
            HAVING cur >= {min_count}
            ORDER BY cur DESC
            LIMIT {int(limit)}
        """
        rows = client.query(query, parameters=params).result_rows
        candidates = []
        for row in rows:
            cur, tot = row[n], row[n + 1]
            baseline = (tot - cur) / bw
            if cur < baseline * mult:
                continue  # within normal range — not anomalous
            entity = {gf: str(row[i]) for i, gf in enumerate(group_fields)}
            candidates.append({
                "entity": entity, "count": cur,
                "first_event": row[n + 2], "last_event": row[n + 3],
            })
        return candidates

    tf, tparams = _stage_time_filter(window, anchor)
    params = {**params, **tparams}

    query = f"""
        SELECT {gb}, count() AS cnt,
               min(timestamp) AS first_ts, max(timestamp) AS last_ts
        FROM {table}
        WHERE {tf} AND ({where})
        GROUP BY {gb}
        HAVING cnt >= {threshold}
        ORDER BY cnt DESC
        LIMIT {int(limit)}
    """
    rows = client.query(query, parameters=params).result_rows
    candidates = []
    for row in rows:
        # Entity is keyed by the join-key name (canonical), so it stays
        # consistent when later stages resolve it against other sources.
        entity = {gf: str(row[i]) for i, gf in enumerate(group_fields)}
        candidates.append({
            "entity": entity,
            "count": row[n],
            "first_event": row[n + 1],
            "last_event": row[n + 2],
        })
    return candidates


def _stage_for_entity(stage: dict, entity: dict, variables: dict,
                      window: int, anchor: Optional[datetime] = None) -> Tuple[bool, dict]:
    """Evaluate a stage for one specific entity within an (optionally anchored)
    window. Returns (matched, result) with event count, time bounds and
    sample evidence."""
    client = ClickHouseClient.get_client()
    source = stage.get("source", DEFAULT_SOURCE)
    table = SOURCE_TABLES.get(source)
    if table is None:
        raise StageEvalError(f"Unknown data source '{source}'")
    threshold = _safe_int(stage.get("threshold", 1), "threshold")

    where, params = _build_where_clause(stage.get("filter", {}) or {}, variables, source)
    ew, eparams = _entity_where(entity, source)
    tf, tparams = _stage_time_filter(window, anchor)
    params = {**params, **eparams, **tparams}
    full_where = f"{tf} AND ({where}) AND ({ew})"

    query = f"""
        SELECT count() AS cnt,
               min(timestamp) AS first_ts, max(timestamp) AS last_ts
        FROM {table}
        WHERE {full_where}
    """
    rows = client.query(query, parameters=params).result_rows
    row = rows[0] if rows else (0, None, None)
    count = row[0]
    if count >= threshold:
        samples = _fetch_stage_samples(source, table, full_where, params)
        return True, {
            "count": count, "first_event": row[1], "last_event": row[2],
            "source": source, "samples": samples,
        }
    return False, {"count": count}


def _rule_join_keys(rule: CorrelationRule, stages: list) -> list:
    """Resolve the columns that link stages into one chain: the rule's
    explicit ``join_keys`` if set, else stage 1's ``group_by``."""
    explicit = _as_list(getattr(rule, "join_keys", None))
    if explicit:
        return explicit
    s1_filter = stages[0].get("filter", {}) or {}
    return _as_list(s1_filter.get("group_by", stages[0].get("group_by")))


def evaluate_correlation_rule(rule: CorrelationRule) -> List[dict]:
    """Evaluate a correlation rule through all its stages.

    Phase 2: returns a list with **one match per entity** whose chain
    satisfies every stage — not just the single busiest entity. In
    ``sequence`` ordering each stage after the first is evaluated in an
    *anchored* window starting at the previous stage's last event, so the
    match proves stage B genuinely followed stage A.
    """
    stages = rule.stages
    if not stages or not isinstance(stages, list):
        return []

    ordering = (getattr(rule, "ordering", "sequence") or "sequence").lower()
    rule_version = getattr(rule, "version", 1) or 1

    try:
        join_keys = _rule_join_keys(rule, stages)

        # ── Stage 1 — gather candidate entities ──────────────────────
        s1 = stages[0]
        w1 = _safe_int(s1.get("window", 300), "window")
        if join_keys:
            candidates = _stage_candidates(s1, join_keys, {}, w1, anchor=None)
        else:
            # No join keys: a single global "entity".
            matched, res = _stage_for_entity(s1, {}, {}, w1, anchor=None)
            candidates = [{"entity": {}, "count": res.get("count", 0),
                           "first_event": res.get("first_event"),
                           "last_event": res.get("last_event")}] if matched else []
        if not candidates:
            return []

        # Each candidate becomes a chain we try to extend stage by stage.
        chains = []
        for cand in candidates:
            entity = cand["entity"]
            chains.append({
                "entity": entity,
                "variables": {"stage1": {**entity,
                                         "key": "|".join(entity.values()),
                                         "count": cand["count"]}},
                "last_event": cand["last_event"],
                "stage1_window": w1,
            })

        # ── Stages 2..N — narrow the candidate set ───────────────────
        stage_evidence = {id(c): [] for c in chains}  # chain -> [stage_result,...]
        for idx in range(1, len(stages)):
            stage = stages[idx]
            wN = _safe_int(stage.get("window", 300), "window")
            survivors = []
            for chain in chains:
                anchor = chain["last_event"] if ordering == "sequence" else None
                matched, res = _stage_for_entity(
                    stage, chain["entity"], chain["variables"], wN, anchor)
                if not matched:
                    continue
                chain["variables"][f"stage{idx + 1}"] = {**chain["entity"], **res}
                if res.get("last_event"):
                    chain["last_event"] = res["last_event"]
                stage_evidence[id(chain)].append({
                    "name": stage.get("name", f"Stage {idx + 1}"),
                    "matched": True, "window": wN,
                    "filter": stage.get("filter", {}),
                    "threshold": stage.get("threshold", 1),
                    "sequence_ok": ordering == "sequence",
                    **res,
                })
                survivors.append(chain)
            chains = survivors
            if not chains:
                return []

        # ── Build one match per surviving chain ──────────────────────
        entity_type = ("composite" if len(join_keys) > 1
                       else _entity_type_for_field(join_keys[0]) if join_keys
                       else "none")
        now_naive = datetime.now(timezone.utc).replace(tzinfo=None)
        matches = []
        for chain in chains:
            # Re-evaluate stage 1 for this entity to capture per-entity
            # evidence (count, time bounds, samples).
            s1_matched, s1_res = _stage_for_entity(s1, chain["entity"], {}, w1, anchor=None)
            s1_result = {
                "name": s1.get("name", "Stage 1"), "matched": True,
                "window": w1, "filter": s1.get("filter", {}),
                "threshold": s1.get("threshold", 1),
                **(s1_res if s1_matched else {}),
            }
            stage_results = [s1_result] + stage_evidence[id(chain)]

            event_times = [t for sr in stage_results
                           for t in (sr.get("first_event"), sr.get("last_event"))
                           if t is not None]
            total_events = sum(sr.get("count", 0) for sr in stage_results)
            entity_value = "|".join(chain["entity"].values())
            fingerprint = match_fingerprint(rule.id, rule_version,
                                            entity_type, entity_value)
            matches.append({
                "rule_id": rule.id,
                "rule_name": rule.name,
                "rule_version": rule_version,
                "severity": rule.severity,
                "ordering": ordering,
                "stages": stage_results,
                "total_events": total_events,
                "mitre_tactic": rule.mitre_tactic,
                "mitre_technique": rule.mitre_technique,
                "key_value": entity_value,
                "entity_type": entity_type,
                "entity_value": entity_value,
                "match_fingerprint": fingerprint,
                "first_seen": min(event_times) if event_times else now_naive,
                "last_seen": max(event_times) if event_times else now_naive,
            })
        return matches

    except StageEvalError as e:
        logger.warning(f"Correlation rule '{rule.name}' not evaluated: {e}")
        return []
    except Exception as e:
        logger.error(f"Error evaluating correlation rule '{rule.name}': {e}")
        return []


def preview_correlation_rule(rule: CorrelationRule, sample_limit: int = 5) -> dict:
    """Dry-run a rule against recent history and return per-stage diagnostics.

    Read-only: queries ClickHouse but never records a match or creates an
    alert. Drives the builder's "Test Rule" button so an analyst can see how
    a rule behaves — and where its chain breaks — before enabling it.
    """
    diag = {
        "ok": False, "matched_chains": 0, "stages": [],
        "sample_matches": [], "estimated_per_hour": 0.0, "error": None,
    }
    stages = rule.stages
    if not stages or not isinstance(stages, list):
        diag["error"] = "Rule has no stages."
        return diag

    ordering = (getattr(rule, "ordering", "sequence") or "sequence").lower()
    try:
        join_keys = _rule_join_keys(rule, stages)

        # Stage 1 — candidate entities
        s1 = stages[0]
        w1 = _safe_int(s1.get("window", 300), "window")
        if join_keys:
            candidates = _stage_candidates(s1, join_keys, {}, w1, anchor=None)
        else:
            matched, res = _stage_for_entity(s1, {}, {}, w1, anchor=None)
            candidates = ([{"entity": {}, "count": res.get("count", 0),
                            "first_event": res.get("first_event"),
                            "last_event": res.get("last_event")}]
                          if matched else [])
        diag["stages"].append({
            "index": 1, "name": s1.get("name", "Stage 1"),
            "result": len(candidates),
            "label": "candidate entities", "error": None,
        })

        chains = [{
            "entity": c["entity"],
            "variables": {"stage1": {**c["entity"], "count": c["count"]}},
            "last_event": c["last_event"],
        } for c in candidates]

        # Stages 2..N — narrow
        for idx in range(1, len(stages)):
            stage = stages[idx]
            wN = _safe_int(stage.get("window", 300), "window")
            survivors = []
            for chain in chains:
                anchor = chain["last_event"] if ordering == "sequence" else None
                matched, res = _stage_for_entity(
                    stage, chain["entity"], chain["variables"], wN, anchor)
                if matched:
                    chain["variables"][f"stage{idx + 1}"] = {**chain["entity"], **res}
                    if res.get("last_event"):
                        chain["last_event"] = res["last_event"]
                    survivors.append(chain)
            diag["stages"].append({
                "index": idx + 1, "name": stage.get("name", f"Stage {idx + 1}"),
                "result": len(survivors),
                "label": "chains surviving", "error": None,
            })
            chains = survivors
            if not chains:
                break

        diag["matched_chains"] = len(chains)
        diag["ok"] = len(chains) > 0
        for chain in chains[:sample_limit]:
            diag["sample_matches"].append({
                "entity": "|".join(chain["entity"].values()) or "(global)",
            })

        # Rough fire-rate estimate. Discrete rules record an entity once per
        # suppress_window; recurring rules record every ~60s evaluation.
        mode = getattr(rule, "match_mode", "discrete") or "discrete"
        sw = getattr(rule, "suppress_window", 3600) or 3600
        per_hour = (3600.0 / sw) if mode == "discrete" else 60.0
        diag["estimated_per_hour"] = round(len(chains) * per_hour, 1)
        return diag

    except StageEvalError as e:
        diag["error"] = str(e)
        diag["stages"].append({
            "index": len(diag["stages"]) + 1, "name": "(failed)",
            "result": 0, "label": "error", "error": str(e),
        })
        return diag
    except Exception as e:
        logger.error(f"Preview error for rule '{getattr(rule, 'name', '?')}': {e}")
        diag["error"] = str(e)
        return diag


def record_correlation_match(match: dict):
    """Record a correlation match in ClickHouse.

    ``timestamp`` is the engine evaluation time; ``first_seen`` / ``last_seen``
    are the event-chain time bounds drawn from the matched evidence.
    """
    try:
        client = ClickHouseClient.get_client()
        now = datetime.now(timezone.utc)
        n_stages = len(match["stages"])

        client.insert("correlation_matches",
            [[
                now,
                match["rule_id"],
                match["rule_name"],
                match["severity"],
                n_stages,
                n_stages,
                json.dumps(match["stages"], default=str),
                match.get("key_value", "") or "",
                match.get("total_events", 0),
                match.get("mitre_tactic", "") or "",
                match.get("mitre_technique", "") or "",
                match.get("rule_version", 1) or 1,
                match.get("match_fingerprint", "") or "",
                match.get("entity_type", "") or "",
                match.get("entity_value", "") or "",
                match.get("first_seen") or now,
                match.get("last_seen") or now,
                "open",
            ]],
            column_names=[
                "timestamp", "rule_id", "rule_name", "severity",
                "stages_matched", "total_stages", "stage_details",
                "key_value", "total_events", "mitre_tactic", "mitre_technique",
                "rule_version", "match_fingerprint", "entity_type",
                "entity_value", "first_seen", "last_seen", "status",
            ]
        )
    except Exception as e:
        logger.error(f"Failed to record correlation match: {e}")


async def create_correlation_alert(match: dict):
    """Create an alert from a correlation match.

    Deduplicates on the exact alert title — which carries both the rule name
    and the implicated entity — so a noisy entity and a genuinely new entity
    no longer suppress each other (the old check matched the rule name only).
    """
    try:
        entity = match.get("entity_value", match.get("key_value", "")) or ""
        title = f"Correlation: {match['rule_name']} [{entity}]"

        async with async_session_maker() as db:
            from sqlalchemy import and_, func
            recent = await db.execute(
                select(func.count(Alert.id)).where(
                    and_(
                        Alert.title == title,
                        Alert.triggered_at > _recent_alert_cutoff(),
                    )
                )
            )
            if recent.scalar() > 0:
                return  # this rule+entity already alerted recently

            stages_summary = " -> ".join(
                f"{s['name']} ({s.get('count', 0)} events)"
                for s in match["stages"]
            )

            alert = Alert(
                title=title,
                severity=match["severity"],
                status="new",
                details=json.dumps({
                    "correlation_rule": match["rule_name"],
                    "rule_version": match.get("rule_version", 1),
                    "match_fingerprint": match.get("match_fingerprint", ""),
                    "entity_type": match.get("entity_type", ""),
                    "entity_value": entity,
                    "stages": match["stages"],
                    "total_events": match["total_events"],
                    "key_value": match.get("key_value", ""),
                    "attack_chain": stages_summary,
                    "first_seen": match.get("first_seen"),
                    "last_seen": match.get("last_seen"),
                    "mitre_tactic": match.get("mitre_tactic", ""),
                    "mitre_technique": match.get("mitre_technique", ""),
                }, default=str),
                triggered_at=datetime.now(timezone.utc),
            )
            db.add(alert)
            await db.commit()
            logger.info(f"Correlation alert created: {title}")
    except Exception as e:
        logger.error(f"Failed to create correlation alert: {e}")


# ── Phase 5: entity risk scoring & incident grouping ────────────────────
SEVERITY_RISK = {"critical": 100, "high": 50, "medium": 20, "low": 5}
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
INCIDENT_GROUP_WINDOW = 3600          # seconds: matches for one entity group
RISK_HALF_LIFE_SECONDS = 86400        # 24h: an entity's risk halves each day
INCIDENT_MATCH_EVIDENCE_CAP = 50      # cap on stored match summaries


def _rule_risk_contribution(rule) -> int:
    """Risk points a match of this rule adds to its entity — the rule's
    explicit ``risk_score``, or a value derived from its severity."""
    rs = getattr(rule, "risk_score", 0) or 0
    if rs > 0:
        return int(rs)
    return SEVERITY_RISK.get((rule.severity or "medium").lower(), 20)


def severity_from_risk(risk: float) -> str:
    """Map an accumulated, decayed risk score to an incident severity."""
    if risk >= 200:
        return "critical"
    if risk >= 100:
        return "high"
    if risk >= 40:
        return "medium"
    return "low"


def _max_severity(a: str, b: str) -> str:
    """Return the higher of two severity labels."""
    return a if _SEVERITY_RANK.get(a, 0) >= _SEVERITY_RANK.get(b, 0) else b


def record_entity_risk(match: dict, score: int):
    """Append a time-stamped risk contribution for the match's entity."""
    try:
        client = ClickHouseClient.get_client()
        client.insert(
            "entity_risk",
            [[
                datetime.now(timezone.utc),
                match.get("entity_type", "") or "",
                match.get("entity_value", "") or "",
                float(score),
                match.get("rule_id", 0) or 0,
                match.get("rule_name", "") or "",
                match.get("match_fingerprint", "") or "",
            ]],
            column_names=["timestamp", "entity_type", "entity_value", "score",
                          "rule_id", "rule_name", "match_fingerprint"],
        )
    except Exception as e:
        logger.error(f"Failed to record entity risk: {e}")


def compute_entity_risk(entity_value: str) -> float:
    """An entity's current risk — the sum of its risk contributions with
    exponential time-decay (24h half-life)."""
    if not entity_value:
        return 0.0
    try:
        client = ClickHouseClient.get_client()
        r = client.query(
            "SELECT sum(score * pow(2, -dateDiff('second', timestamp, now()) / "
            "{hl:Float64})) FROM entity_risk "
            "WHERE entity_value = {ev:String} AND timestamp > now() - INTERVAL 30 DAY",
            parameters={"ev": entity_value, "hl": float(RISK_HALF_LIFE_SECONDS)},
        )
        val = r.result_rows[0][0] if r.result_rows else None
        return round(float(val), 1) if val is not None else 0.0
    except Exception as e:
        logger.error(f"Failed to compute entity risk: {e}")
        return 0.0


async def group_into_incident(db, match: dict, risk: float):
    """Group a recorded match into an open incident for the same entity, or
    open a new one — so related matches become one prioritized incident
    rather than a flat alert stream."""
    try:
        from sqlalchemy import and_
        entity = match.get("entity_value", "") or ""
        if not entity:
            return
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=INCIDENT_GROUP_WINDOW)

        result = await db.execute(
            select(CorrelationIncident).where(and_(
                CorrelationIncident.entity_value == entity,
                CorrelationIncident.status.in_(("new", "investigating")),
                CorrelationIncident.last_seen > cutoff,
            )).order_by(CorrelationIncident.last_seen.desc()).limit(1)
        )
        incident = result.scalar_one_or_none()

        evidence = {
            "timestamp": str(match.get("first_seen") or now),
            "rule_name": match.get("rule_name", ""),
            "rule_id": match.get("rule_id", 0),
            "severity": match.get("severity", ""),
            "total_events": match.get("total_events", 0),
            "fingerprint": match.get("match_fingerprint", ""),
            "chain": " -> ".join(s.get("name", "") for s in match.get("stages", [])),
        }
        tactic = match.get("mitre_tactic") or ""
        sev = _max_severity(severity_from_risk(risk), match.get("severity", "medium"))

        if incident:
            incident.match_count = (incident.match_count or 0) + 1
            incident.risk_score = risk
            incident.severity = _max_severity(incident.severity or "low", sev)
            incident.last_seen = now
            names = list(incident.rule_names or [])
            if match.get("rule_name") and match["rule_name"] not in names:
                names.append(match["rule_name"])
            incident.rule_names = names
            tactics = list(incident.mitre_tactics or [])
            if tactic and tactic not in tactics:
                tactics.append(tactic)
            incident.mitre_tactics = tactics
            incident.matches = ([evidence] + list(incident.matches or [])
                                )[:INCIDENT_MATCH_EVIDENCE_CAP]
        else:
            db.add(CorrelationIncident(
                entity_type=match.get("entity_type", "ip") or "ip",
                entity_value=entity,
                status="new",
                severity=sev,
                risk_score=risk,
                match_count=1,
                rule_names=[match["rule_name"]] if match.get("rule_name") else [],
                mitre_tactics=[tactic] if tactic else [],
                matches=[evidence],
                first_seen=now,
                last_seen=now,
            ))
            # Flush so a later match for this same entity — in this same
            # evaluation run — groups into this incident instead of opening
            # another (the session has autoflush disabled).
            await db.flush()
    except Exception as e:
        logger.error(f"Failed to group match into incident: {e}")


def _post_webhook(url: str, payload: dict):
    """POST a JSON payload to a webhook URL (blocking — run in a thread)."""
    data = json.dumps(payload, default=str).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "Zentryc-Correlation"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        resp.read(1)


async def fire_response_actions(rule, match: dict):
    """Fire a rule's configured response actions for a recorded match.

    Phase 6: supports ``webhook`` (POST the match summary to a URL) and
    ``log`` (structured log line). More action types — notifications, EDL
    blocklisting, ticketing — plug into the same dispatch.
    """
    actions = getattr(rule, "actions", None) or []
    if not isinstance(actions, list) or not actions:
        return
    summary = {
        "event": "correlation_match",
        "rule": match.get("rule_name"),
        "rule_id": match.get("rule_id"),
        "severity": match.get("severity"),
        "entity_type": match.get("entity_type"),
        "entity_value": match.get("entity_value"),
        "match_fingerprint": match.get("match_fingerprint"),
        "total_events": match.get("total_events"),
        "mitre_tactic": match.get("mitre_tactic"),
        "mitre_technique": match.get("mitre_technique"),
        "first_seen": str(match.get("first_seen")),
        "last_seen": str(match.get("last_seen")),
    }
    for action in actions:
        try:
            atype = (action or {}).get("type")
            if atype == "webhook" and action.get("url"):
                await asyncio.to_thread(_post_webhook, action["url"], summary)
                logger.info(f"Response action: webhook fired for '{match.get('rule_name')}'")
            elif atype == "log":
                level = (action.get("level") or "warning").lower()
                msg = (f"Correlation response — rule '{match.get('rule_name')}' "
                       f"matched entity {match.get('entity_value')} "
                       f"(severity {match.get('severity')})")
                (logger.error if level == "error" else logger.warning)(msg)
        except Exception as e:
            logger.error(f"Response action {action!r} failed: {e}")


async def evaluate_all_correlation_rules():
    """Evaluate all enabled correlation rules. Called by the scheduler."""
    try:
        async with async_session_maker() as db:
            result = await db.execute(
                select(CorrelationRule).where(CorrelationRule.is_enabled == True)
            )
            rules = result.scalars().all()

            if not rules:
                return

            matched_count = 0
            suppressed_count = 0
            for rule in rules:
                try:
                    # Phase 2: a rule can match multiple entities in one pass.
                    matches = evaluate_correlation_rule(rule)
                    mode = getattr(rule, "match_mode", "discrete") or "discrete"
                    window = getattr(rule, "suppress_window", 3600) or 3600

                    recorded = 0
                    for match in matches:
                        # Discrete rules record a given (rule, entity) chain at
                        # most once per suppression window — so match counts
                        # measure distinct chains, not 60-second scheduler ticks.
                        # Recurring rules are intentional monitors: always record.
                        if mode == "discrete" and _is_match_suppressed(
                                match["match_fingerprint"], window):
                            suppressed_count += 1
                            continue
                        record_correlation_match(match)
                        await create_correlation_alert(match)
                        # Phase 5: contribute risk to the entity and group
                        # the match into an incident.
                        score = _rule_risk_contribution(rule)
                        record_entity_risk(match, score)
                        risk = compute_entity_risk(match["entity_value"]) + score
                        await group_into_incident(db, match, risk)
                        await fire_response_actions(rule, match)
                        recorded += 1

                    if recorded:
                        matched_count += recorded
                        rule.last_triggered_at = datetime.now(timezone.utc)
                        rule.trigger_count = (rule.trigger_count or 0) + recorded

                    rule.last_evaluated_at = datetime.now(timezone.utc)
                except Exception as e:
                    logger.error(f"Error evaluating correlation rule '{rule.name}': {e}")

            await db.commit()

            if matched_count or suppressed_count:
                logger.info(
                    f"Correlation engine: {matched_count} recorded, "
                    f"{suppressed_count} suppressed (already recorded in window), "
                    f"of {len(rules)} rules"
                )

    except Exception as e:
        logger.error(f"Correlation engine error: {e}")


async def seed_correlation_rules():
    """Seed pre-built correlation rules."""
    async with async_session_maker() as db:
        # Check existing rules
        result = await db.execute(select(CorrelationRule.name))
        existing = {r[0] for r in result.all()}

        rules = [
            {
                "name": "Reconnaissance then Access",
                "description": "Port scan (>10 denied ports) followed by allowed connection from same IP within 10 minutes.",
                "severity": "high",
                "stages": [
                    {
                        "name": "Port Scan Detected",
                        "filter": {"action": "deny", "group_by": "srcip"},
                        "threshold": 10,
                        "window": 300,
                    },
                    {
                        "name": "Successful Access",
                        "filter": {"action": "allow", "srcip": "$stage1.srcip"},
                        "threshold": 1,
                        "window": 600,
                    },
                ],
                "mitre_tactic": "Initial Access",
                "mitre_technique": "T1190 - Exploit Public-Facing Application",
            },
            {
                "name": "Brute Force then Login",
                "description": "Multiple denied connections followed by allowed connection from same source IP.",
                "severity": "critical",
                "stages": [
                    {
                        "name": "Multiple Denials",
                        "filter": {"action": "deny", "group_by": "srcip"},
                        "threshold": 20,
                        "window": 300,
                    },
                    {
                        "name": "Successful Login",
                        "filter": {"action": "allow", "srcip": "$stage1.srcip"},
                        "threshold": 1,
                        "window": 600,
                    },
                ],
                "mitre_tactic": "Credential Access",
                "mitre_technique": "T1110 - Brute Force",
            },
            {
                "name": "Multi-Firewall Scan",
                "description": "Same source IP denied on 3+ different firewalls within 5 minutes.",
                "severity": "high",
                "stages": [
                    {
                        "name": "Multi-Device Denials",
                        "filter": {"action": "deny", "group_by": "srcip"},
                        "threshold": 15,
                        "window": 300,
                    },
                ],
                "mitre_tactic": "Reconnaissance",
                "mitre_technique": "T1595 - Active Scanning",
            },
            {
                "name": "Denied then Allowed - Same Source",
                "description": "Source IP denied multiple times then allowed through. Possible policy bypass or misconfiguration.",
                "severity": "medium",
                "stages": [
                    {
                        "name": "Repeated Denials",
                        "filter": {"action": "deny", "group_by": "srcip"},
                        "threshold": 5,
                        "window": 600,
                    },
                    {
                        "name": "Access Granted",
                        "filter": {"action": "allow", "srcip": "$stage1.srcip"},
                        "threshold": 1,
                        "window": 900,
                    },
                ],
                "mitre_tactic": "Defense Evasion",
                "mitre_technique": "T1562 - Impair Defenses",
            },
            {
                "name": "High Volume Outbound Traffic",
                "description": "Single internal IP sending unusually high volume of outbound traffic, potential data exfiltration.",
                "severity": "high",
                "stages": [
                    {
                        "name": "High Outbound Volume",
                        "filter": {"action": "allow", "group_by": "srcip"},
                        "threshold": 500,
                        "window": 300,
                    },
                ],
                "mitre_tactic": "Exfiltration",
                "mitre_technique": "T1048 - Exfiltration Over Alternative Protocol",
            },
            # ── Phase 4: cross-source correlation rules ──────────────
            {
                "name": "Threat-Intel Source then Firewall Denials",
                "description": "An IP flagged by a threat-intel feed is also generating repeated firewall denials. Cross-source: IOC hits + firewall traffic.",
                "severity": "high",
                "ordering": "any_order",
                "join_keys": ["ip"],
                "stages": [
                    {
                        "name": "Threat-Intel IOC Hit",
                        "source": "ioc_matches",
                        "filter": {"group_by": "ip"},
                        "threshold": 1,
                        "window": 86400,
                    },
                    {
                        "name": "Firewall Denials",
                        "source": "syslogs",
                        "filter": {"action": "deny"},
                        "threshold": 5,
                        "window": 86400,
                    },
                ],
                "mitre_tactic": "Command and Control",
                "mitre_technique": "T1071 - Application Layer Protocol",
            },
            {
                "name": "Suspicious DNS then Outbound Connection",
                "description": "A host queried a security-related DNS category, then opened an allowed outbound connection. Cross-source: DNS logs + firewall traffic.",
                "severity": "medium",
                "ordering": "any_order",
                "join_keys": ["ip"],
                "stages": [
                    {
                        "name": "Security-Category DNS Query",
                        "source": "dns_logs",
                        "filter": {"category": "Information and Computer Security",
                                   "group_by": "ip"},
                        "threshold": 1,
                        "window": 3600,
                    },
                    {
                        "name": "Allowed Outbound Connection",
                        "source": "syslogs",
                        "filter": {"action": "allow"},
                        "threshold": 1,
                        "window": 3600,
                    },
                ],
                "mitre_tactic": "Command and Control",
                "mitre_technique": "T1071.004 - DNS",
            },
            {
                "name": "PA Threat Alert then Firewall Allow",
                "description": "A Palo Alto threat alert was raised for a host that also has allowed firewall traffic. Cross-source: PA threat logs + firewall traffic.",
                "severity": "high",
                "ordering": "any_order",
                "join_keys": ["ip"],
                "stages": [
                    {
                        "name": "PA Threat Alert",
                        "source": "pa_threat_logs",
                        "filter": {"severity": "high", "group_by": "ip"},
                        "threshold": 1,
                        "window": 3600,
                    },
                    {
                        "name": "Allowed Firewall Traffic",
                        "source": "syslogs",
                        "filter": {"action": "allow"},
                        "threshold": 1,
                        "window": 3600,
                    },
                ],
                "mitre_tactic": "Initial Access",
                "mitre_technique": "T1190 - Exploit Public-Facing Application",
            },
        ]

        added = 0
        for rule_data in rules:
            if rule_data["name"] not in existing:
                rule = CorrelationRule(
                    name=rule_data["name"],
                    description=rule_data["description"],
                    severity=rule_data["severity"],
                    stages=rule_data["stages"],
                    mitre_tactic=rule_data.get("mitre_tactic"),
                    mitre_technique=rule_data.get("mitre_technique"),
                    is_enabled=True,
                    ordering=rule_data.get("ordering", "sequence"),
                    join_keys=rule_data.get("join_keys"),
                )
                db.add(rule)
                added += 1

        if added > 0:
            await db.commit()
            logger.info(f"Seeded {added} correlation rules")
