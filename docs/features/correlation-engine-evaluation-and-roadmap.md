# Correlation Engine — Feature Evaluation & Strategic Roadmap

> **Author:** Security Architecture & Product Review
> **Date:** 2026-05-20
> **Scope:** `/correlation/` — Multi-Stage Attack Detection
> **Status:** Draft for review
> **Reviewed build:** Zentryc v3.x — branch `feat/policy-lookup-config-match`

---

## 1. Executive Summary

Zentryc's Correlation Engine is a **working, useful, but early-stage** multi-stage
detection feature. It already does the hard 20%: a staged rule model, variable
substitution between stages, ClickHouse-backed match storage, MITRE ATT&CK
mapping, a per-rule analytics drill-down, and scheduler-driven evaluation every
60 seconds. On the day of review it had **530,271 lifetime matches across 5
seeded rules** — so it is live and producing signal.

However, measured against the modern SIEM/SOAR market (Splunk Enterprise
Security, Microsoft Sentinel Fusion, Elastic Security, CrowdStrike Falcon
Next-Gen SIEM, IBM QRadar, Datadog Cloud SIEM), the feature has **four
structural weaknesses** that limit its credibility as an enterprise capability:

| # | Weakness | Business impact |
|---|----------|-----------------|
| 1 | **Stages do not enforce temporal order.** The engine checks "did X happen in the last N seconds" and "did Y happen in the last M seconds" independently — it never anchors stage 2 to stage 1's match time. A rule named "Recon *then* Access" actually fires on "Recon *and* Access (same IP, overlapping windows)". | False positives; the core promise of "sequence detection" is not delivered. |
| 2 | **Authoring is raw-JSON only.** Analysts hand-write a JSON array of stages in a textarea. No visual builder, no field auto-complete, no validation, no edit (rules can only be created, toggled, or deleted), no test/preview. | High skill barrier; rules are write-once; analysts cannot tune without deleting and recreating. |
| 3 | **Single data source.** Every rule queries one ClickHouse table (`syslogs` — firewall traffic). No correlation across DNS, URL, threat-intel, auth, or alert signals. | Cannot detect cross-domain attack chains, which is the entire point of correlation. |
| 4 | **No risk-based alerting, no ML/anomaly fusion, no response actions.** Matches create a generic `Alert` row. No entity risk scoring, no alert grouping into incidents, no SOAR playbook trigger. | Output is a flat alert stream — the same false-positive fatigue correlation is supposed to solve. |

This document inventories the current implementation, lists **concrete bugs**,
benchmarks against six competitors, and proposes a **6-phase roadmap** that
takes the feature from "staged threshold queries" to a genuine
**risk-based, multi-domain correlation and detection-engineering platform**.

---

## 2. Current State Assessment

### 2.1 Architecture

```
┌──────────────────┐   every 60s    ┌─────────────────────────┐
│ APScheduler      │ ─────────────▶ │ evaluate_all_correlation │
│ (scheduler.py)   │                │ _rules()                │
└──────────────────┘                └───────────┬─────────────┘
                                                 │
                              ┌──────────────────┴───────────────────┐
                              ▼                                      ▼
                  ┌────────────────────────┐          ┌──────────────────────────┐
                  │ PostgreSQL              │          │ ClickHouse                │
                  │ correlation_rules       │          │ syslogs  (event source)   │
                  │  (rule definitions)     │          │ correlation_matches (sink)│
                  └────────────────────────┘          └──────────────────────────┘
                              │                                      │
                              ▼                                      ▼
                  ┌────────────────────────┐          ┌──────────────────────────┐
                  │ Alert (PostgreSQL)     │          │ /correlation/  UI         │
                  │  one row per match     │          │  (rules.html, mitre_map)  │
                  └────────────────────────┘          └──────────────────────────┘
```

**Key files**

| File | Role | LOC |
|------|------|-----|
| `fastapi_app/models/correlation.py` | `CorrelationRule` SQLAlchemy model | 39 |
| `fastapi_app/services/correlation_engine.py` | Stage evaluation, match recording, alert creation, rule seeding | 441 |
| `fastapi_app/api/correlation.py` | UI route + JSON API (list/create/toggle/delete/detail/matches) + MITRE map | 409 |
| `fastapi_app/templates/correlation/rules.html` | Single-page UI (rules grid, detail modal, add-rule modal) | ~2,000 |
| `fastapi_app/templates/correlation/mitre_map.html` | MITRE ATT&CK coverage heat map | ~370 |
| `fastapi_app/services/scheduler.py:426` | 60-second `IntervalTrigger` job | — |

### 2.2 Data model

`CorrelationRule` (PostgreSQL):

- `name`, `description`, `severity`, `is_enabled`
- `stages` — **opaque JSON array**; each stage: `{name, filter, threshold, window, group_by}`
- `mitre_tactic`, `mitre_technique` — free-text strings
- `last_evaluated_at`, `last_triggered_at`, `trigger_count`

`correlation_matches` (ClickHouse, `MergeTree`, 6-month TTL):

- `timestamp, rule_id, rule_name, severity, stages_matched, total_stages,`
  `stage_details (JSON string), key_value, total_events, mitre_tactic, mitre_technique`

### 2.3 Feature inventory (what works today)

✅ **Staged rule model** — ordered list of stages, each with a filter, threshold,
   time window, and optional `group_by`.
✅ **Variable substitution** — `$stage1.srcip` resolves a value captured in an
   earlier stage into a later stage's filter (the "same entity" pivot).
✅ **Comparison operators** — `_gt / _lt / _gte / _lte / _ne` field suffixes.
✅ **Scheduler-driven evaluation** — every 60s, all enabled rules.
✅ **Match persistence** — ClickHouse `correlation_matches`, queryable, TTL'd.
✅ **5 pre-built rules** — Recon→Access, Brute Force→Login, Multi-Firewall Scan,
   Denied→Allowed, High Outbound Volume — each MITRE-mapped.
✅ **Rules grid UI** — per-rule cards: severity, stage flow, MITRE chips,
   24h match count, last triggered/evaluated, enable/disable/delete.
✅ **Per-rule detail dashboard** — time-range pills (1h/6h/24h/7d), match count,
   total events, unique keys, top matched IPs, hourly timeline, recent matches,
   rule configuration breakdown, deep links into the log viewer.
✅ **Recent Matches tab** — cross-rule match feed.
✅ **MITRE ATT&CK coverage map** — 14 tactics, 56 techniques, computes
   coverage % from alert + correlation rule mappings (showed **31%** of
   detectable techniques covered at review time).
✅ **Alert generation** — each match creates an `Alert` with attack-chain summary.
✅ **RBAC** — view = ANALYST, create/toggle/delete = ADMIN.

### 2.4 Screenshots captured during review

- `correlation-main.png` — rules grid + stat cards
- `correlation-rule-detail.png` — per-rule analytics drill-down
- `correlation-recent-matches.png` — recent matches tab
- `correlation-mitre-map.png` — MITRE ATT&CK coverage heat map

---

## 3. Critical Findings — Bugs & Defects

These should be triaged **before** any new feature work. They affect
correctness, security, and stability.

### 3.1 🔴 CRITICAL — Stages are not temporally ordered

`evaluate_correlation_rule()` calls `_evaluate_stage(stage, window, variables)`
and **never passes `reference_time`**. `_evaluate_stage` therefore always uses
its default `reference_time="now()"`.

Consequence: every stage independently asks *"in the last `window` seconds from
**now**, did this filter match `threshold` times?"*. Stage 2 is **not anchored
to stage 1's match time**. "Port scan **then** access" is implemented as "port
scan **and** access by the same IP, both within their own windows ending now."

This means:
- The attack-chain *ordering* a correlation rule is supposed to prove is **not
  proven**.
- A host that was scanned last week and legitimately connects today can match.
- `total_events` sums independent windows, inflating the number.

**Fix:** thread `reference_time` through. Stage 1 should capture the timestamp
of its triggering events; stage 2+ should evaluate
`timestamp BETWEEN stage1_time AND stage1_time + window`. This is the single
most important correctness fix in the document. See §6 Phase 3.

### 3.2 🔴 HIGH — Duplicate-alert check throws `ValueError`

`create_correlation_alert()`:

```python
Alert.triggered_at > datetime.now(timezone.utc).replace(
    minute=datetime.now(timezone.utc).minute - 5
)
```

When the current minute is `0–4`, `minute - 5` is negative and
`datetime.replace()` raises `ValueError: minute must be in 0..59`. The whole
`create_correlation_alert` call is wrapped in a bare `except`, so **the alert is
silently dropped** for the first 5 minutes of every hour. It also does not
subtract across hour boundaries even when it doesn't crash.

**Fix:** `datetime.now(timezone.utc) - timedelta(minutes=5)`.

### 3.3 🟠 MEDIUM — SQL built by string interpolation

`_build_where_clause()` interpolates filter **field names and values** straight
into ClickHouse SQL:

```python
conditions.append(f"{field} = '{value}'")
...
query = f"SELECT {group_by}, count() ... GROUP BY {group_by}"
```

`api_rule_match_detail` escapes only single quotes (`rule.name.replace("'", "\\'")`)
— weak, and field/`group_by` names are unescaped entirely. Rule creation is
ADMIN-only, which lowers the *immediate* risk, but:
- Variable-substituted values (`$stage1.srcip`) are **data-derived** from prior
  ClickHouse results — a tainted-data path.
- Field/`group_by` names control SQL structure with no allow-list.

**Fix:** allow-list valid column names; bind values as ClickHouse query
parameters instead of f-string interpolation.

### 3.4 🟠 MEDIUM — No stage-schema validation

`api_create_rule` accepts `data["stages"]` and stores it verbatim. A malformed
stage (missing `filter`, non-int `threshold`, unknown field) is only discovered
at evaluation time, where it is swallowed by `except Exception` in
`_evaluate_stage` and logged — the rule silently never fires. The analyst gets
no feedback.

**Fix:** Pydantic schema for stages (`schemas/correlation.py`), validated on
create/update.

### 3.5 🟡 LOW — Dead "View All Matches" link

In the rule detail modal the **View All Matches** control links to `#` — it does
nothing. Either wire it to a filtered Recent Matches view or remove it.

### 3.6 🟡 LOW — No edit path

The API exposes create, toggle, delete — **no update**. Tuning a threshold means
deleting the rule (losing `trigger_count` history and its `correlation_matches`
lineage by `rule_id`) and recreating it. `updated_at` exists on the model but is
never used.

### 3.7 🟡 LOW — Full-scan evaluation, no incremental cursor

Every 60s, every enabled rule re-runs a full windowed aggregation over
`syslogs`. With the seeded "5-minute window" rules this is tolerable, but it
scales O(rules × window × EPS) and re-counts the same events every cycle. There
is no per-rule evaluation cursor / watermark. At higher rule counts this
becomes a ClickHouse load problem.

### 3.8 🟡 LOW — `match_stats` severity card omits medium/low

`correlation_rules_page` populates only `critical` and `high` counters from the
severity aggregation; `medium`/`low` matches are computed but never surfaced.
The "Denied then Allowed" rule (medium) contributes to `total` but to no
severity card.

---

## 4. Competitive Analysis

Benchmarked against the products enterprise buyers will compare Zentryc to.

### 4.1 Splunk Enterprise Security — *Correlation Searches*

- **Guided search wizard** builds SPL from data-source / time-range / filter /
  aggregate / split-by choices — no raw query writing required.
- **Real-time vs scheduled** execution; **index-time** ranges catch late-arriving
  data.
- **Adaptive Response Actions** — a match can run notable-event creation, risk
  modifiers, notifications, scripts, ticketing.
- **Throttling** — suppress duplicate notables per field for a window.
- **Trigger conditions** — fire only when result count / pattern conditions met.
- **Annotations** — enrich results with MITRE ATT&CK, CIS, Kill Chain
  framework mappings, surfaced in Incident Review.
- **Risk-Based Alerting (RBA)** — searches contribute *risk scores* to
  risk objects; a separate search alerts when cumulative risk crosses a
  threshold.

### 4.2 Microsoft Sentinel — *Fusion / Advanced Multistage Attack Detection*

- **Fusion** is an **ML correlation engine**: it stitches low-fidelity
  signals/anomalies from many sources into a **single high-fidelity incident**.
- **Entity-based correlation** — matching pivots on entities (user, IP, host);
  rules *must* emit entity mappings or Fusion cannot correlate.
- **Kill-chain (tactics) awareness** — alerts carry tactic metadata.
- Output is an **Incident**, not another alert — explicitly designed to *reduce*
  alert volume.
- **Enabled by default**; near-zero configuration.
- Scheduled analytics rules also support **NRT (near-real-time)**, **anomaly**
  rule types, and **alert grouping** into incidents.

### 4.3 Elastic Security — *Event Correlation (EQL) rules*

- **EQL sequence queries**: `sequence by host.id [event A] [event B] [event C]`
  with `with maxspan=5m` — **true ordered, time-bounded sequences**.
- Sequences can require **shared join fields** (`by host.id`) — entity pivot.
- Supports **single complex events, sequences, and absence of expected events**.
- Rule types: query, threshold, EQL, ML, indicator-match (threat intel),
  new-terms.
- **Building / testing in the UI** with a rule preview before enabling.

### 4.4 IBM QRadar — *Rules, Building Blocks, Offense Chaining*

- **Building Blocks** — reusable, action-less test groups composed into rules
  with AND/OR — modular detection content.
- **AND/OR rule composition** over events, flows, and offenses.
- **Offense chaining** — related offenses are chained to cut analyst review load.
- **Stateful rule tests** with counters and time windows.

### 4.5 CrowdStrike Falcon Next-Gen SIEM

- **1,000+ correlation rule templates** across cloud, endpoint, network,
  identity, SaaS.
- **Rule Template Discovery dashboard** — recommends templates that match the
  data sources you actually ingest, instead of a flat library to scroll.
- Visual rule builder; MITRE-aligned content.

### 4.6 Datadog Cloud SIEM — *Signal Correlation Rules*

- Dedicated rule type that **correlates existing detection signals** (not raw
  logs) into a higher-severity signal.
- Visual builder for the correlation logic; correlate by shared entity.
- Reduces noise by promoting clusters of related signals.

### 4.7 Feature comparison matrix

| Capability | **Zentryc today** | Splunk ES | Sentinel | Elastic | QRadar | CrowdStrike |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| Multi-stage / sequence rules | ⚠️ unordered | ✅ | ✅ | ✅ | ✅ | ✅ |
| **True temporal ordering** | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Visual / no-code rule builder | ❌ raw JSON | ✅ wizard | ✅ | ✅ | ✅ | ✅ |
| Edit existing rule | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Test / preview before enable | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Multi-source correlation | ❌ syslog only | ✅ | ✅ | ✅ | ✅ | ✅ |
| AND / OR logic | ❌ AND-chain only | ✅ | ✅ | ✅ | ✅ | ✅ |
| Absence-of-event detection | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Entity-based correlation | ⚠️ IP string only | ✅ | ✅ | ✅ | ✅ | ✅ |
| Risk-based alerting / scoring | ❌ | ✅ | ✅ | ⚠️ | ⚠️ | ✅ |
| ML / anomaly fusion | ❌ | ✅ | ✅ | ✅ | ⚠️ | ✅ |
| Alert → incident grouping | ❌ flat alerts | ✅ | ✅ | ✅ | ✅ chaining | ✅ |
| Throttling / suppression | ⚠️ crude 5-min | ✅ | ✅ | ✅ | ✅ | ✅ |
| Response actions / SOAR | ❌ alert only | ✅ | ✅ | ✅ | ✅ | ✅ |
| Rule template library | ⚠️ 5 seeds | ✅ | ✅ | ✅ 1000s | ✅ | ✅ 1000+ |
| MITRE ATT&CK mapping | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| MITRE coverage heat map | ✅ strong | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ |
| Per-rule analytics drill-down | ✅ strong | ✅ | ✅ | ✅ | ✅ | ✅ |

**Legend:** ✅ full · ⚠️ partial · ❌ absent

### 4.8 Where Zentryc already competes well

- The **MITRE ATT&CK coverage heat map** is genuinely strong — most competitors
  bury this or sell it as a separate module. Keep investing here; it is a
  differentiator and a natural sales demo.
- The **per-rule analytics drill-down** (top entities, timeline, recent matches,
  log deep-links) is more polished than QRadar's default and on par with
  Elastic. This is a real strength.
- **Scheduler-driven, ClickHouse-backed** evaluation is a sound, scalable
  foundation — the architecture is right; the detection *semantics* are what
  need work.

---

## 5. Gap Analysis Summary

Ranked by severity-to-fix-vs-value:

1. **Detection correctness** — stages must be ordered and time-bounded (§3.1).
   Without this the feature does not do what its name claims.
2. **Authoring experience** — visual builder, edit, validation, test/preview.
   This is the difference between a feature analysts *can* use and one they
   *will* use.
3. **Detection breadth** — multi-source correlation, AND/OR, absence detection,
   true entity model. This unlocks the cross-domain chains that justify a
   correlation engine.
4. **Output quality** — risk-based alerting, incident grouping, suppression.
   This converts a noisy alert stream into prioritized, defensible incidents.
5. **Detection content & intelligence** — template library, ML/anomaly
   contribution, automated MITRE gap-to-rule suggestions.
6. **Response** — SOAR playbook actions wired to matches.

---

## 6. Improvement & Enhancement Roadmap

Six phases. Each phase is independently shippable and delivers user-visible
value. Effort estimates are engineering-weeks for one full-stack engineer.

---

### Phase 1 — Correctness & Hardening *(must-do — ~1.5 weeks)*

**Goal:** make the existing feature trustworthy.

| Task | File(s) | Effort |
|------|---------|--------|
| Fix duplicate-alert `ValueError` (§3.2) | `correlation_engine.py` | 0.5d |
| Allow-list columns + parameterized ClickHouse queries (§3.3) | `correlation_engine.py`, `api/correlation.py` | 2d |
| Pydantic `CorrelationRuleSchema` + `StageSchema`, validate on create (§3.4) | new `schemas/correlation.py` | 2d |
| Surface medium/low severity counts in stat cards (§3.8) | `api/correlation.py`, `rules.html` | 0.5d |
| Wire or remove "View All Matches" dead link (§3.5) | `rules.html` | 0.5d |
| Add `PUT /api/correlation/rules/{id}` update endpoint (§3.6) | `api/correlation.py` | 1d |
| Unit tests for `_build_where_clause`, `_evaluate_stage`, alert dedup | new `tests/test_correlation.py` | 2d |

**Exit criteria:** no silent failures; rules can be edited; queries are
injection-safe; CI has correlation coverage.

---

### Phase 2 — Authoring Experience: Visual Rule Builder *(~3 weeks)*

**Goal:** eliminate raw-JSON authoring. This is the highest-visibility UX win.

- **Visual stage builder** — replace the JSON textarea with a stage-card UI:
  - Add / remove / reorder stages (drag handle).
  - Per-stage: name, data source (dropdown), filter conditions (field
    dropdown + operator dropdown + value, with AND between conditions),
    threshold (number), window (duration picker), group-by (field dropdown).
  - Variable picker — when filling a later stage, offer
    `$stage1.<field>` chips for fields captured upstream.
  - Field dropdowns populated from a **schema catalog** of `syslogs`
    columns (later: per-source schemas).
- **Edit mode** — open any existing rule in the same builder (depends on the
  Phase 1 update endpoint).
- **Live JSON view** — collapsible "Advanced (JSON)" panel for power users; the
  builder and JSON stay in sync (keep the escape hatch).
- **Test / Preview** — `POST /api/correlation/rules/test` runs the draft rule
  against the last N hours **without persisting** and returns: stages matched,
  sample matches, event counts, estimated fire frequency. Inspired by Elastic's
  rule preview and Splunk's wizard. Critical for tuning.
- **Clone rule** — duplicate as a starting point.
- **Inline validation** — name uniqueness, threshold > 0, window sanity,
  unknown-field warnings, surfaced before save.

**New endpoints:** `POST /api/correlation/rules/test`,
`GET /api/correlation/schema` (field catalog), `POST .../rules/{id}/clone`.

**Exit criteria:** a VIEWER-level analyst can build, test, and tune a
correlation rule without writing JSON.

---

### Phase 3 — Detection Depth: True Sequencing & Logic *(~4 weeks)*

**Goal:** make "multi-stage" mean what it says.

- **Temporal ordering (fixes §3.1)** — thread `reference_time` through
  `evaluate_correlation_rule`. Stage 1 captures `min/max` event timestamps of
  its match; stage *n* evaluates
  `timestamp BETWEEN stage(n-1).end AND stage(n-1).end + window`.
  Add a per-rule `ordering` mode: `sequence` (strict order) vs
  `any-order` (current behavior, kept for back-compat).
- **AND / OR within a stage** — filter conditions become a small condition
  tree, not a flat dict. Borrow QRadar's building-block composition.
- **Negative / absence stages** — "stage A occurred and stage B did *not*
  occur within `window`". Elastic, Splunk, Sentinel all support this; it is
  essential for detections like "login with no preceding MFA event".
- **Stage join keys beyond a single IP** — allow `group_by`/join on
  `(srcip)`, `(srcip, dstip)`, `username`, `host`, etc. — a real composite
  entity key, not a single string.
- **Per-stage negation operators** — `not in`, `not equals`, CIDR membership,
  regex match.

**Schema change:** `correlation_rules` gains `ordering` (string) and `version`
(int); stage JSON schema extended (condition tree, `negate` flag, composite
`join_keys`). Provide an Alembic migration + a one-time converter for the 5
seeded rules.

**Exit criteria:** "Recon then Access" only fires when recon genuinely
precedes access by the same entity inside the window.

---

### Phase 4 — Multi-Source Correlation & Entity Model *(~4 weeks)*

**Goal:** correlate across domains, not just firewall traffic.

- **Pluggable data sources** — each stage declares a `source`:
  `syslogs` (firewall), `dns_logs`, `url_logs`, `auth_events`,
  `threat_intel_hits`, `alerts` (correlate Zentryc's own alerts — the Datadog
  "signal correlation" model), `correlation_matches` (meta-correlation).
- **Source registry** — `services/correlation_sources.py` mapping each source
  to its ClickHouse table, schema, timestamp column, and entity fields.
- **Entity normalization** — introduce a lightweight entity concept
  (`ip`, `user`, `host`, `domain`). Each source maps its native fields to
  canonical entities so a stage on `dns_logs.client_ip` can join a stage on
  `syslogs.srcip` as the same `ip` entity. This is the Sentinel-Fusion
  prerequisite: *no entity mapping → no cross-source correlation*.
- **Cross-source example rules** to seed:
  - "Newly-registered domain DNS lookup → outbound connection to its IP →
    high data volume" (C2 + exfil).
  - "Threat-intel IOC hit → allowed firewall connection from same host."
  - "Multiple failed auth → URL access to admin path → config change."

**Exit criteria:** at least 3 shipped rules that span ≥2 data sources.

---

### Phase 5 — Output Quality: Risk-Based Alerting & Incidents *(~3 weeks)*

**Goal:** turn matches into prioritized, deduplicated incidents.

- **Entity risk scoring (RBA)** — each correlation match contributes a
  weighted risk score to the entity (IP/user/host) it implicates. A separate
  evaluator raises a **high-fidelity incident** when an entity's cumulative
  risk over a rolling window crosses a threshold. This is the Splunk RBA /
  Sentinel Fusion model and the single biggest noise-reduction lever.
  - New ClickHouse table `entity_risk` (entity, score, contributing rules,
    decay).
  - Time-decay so stale risk ages out.
- **Incident grouping** — matches sharing an entity + time proximity collapse
  into one incident instead of N alerts. Add an `Incident` concept (or reuse
  the existing alert model with a parent/child relation).
- **Proper throttling / suppression** — replace the crude 5-minute title
  match with configurable per-rule suppression: suppress by entity for
  `suppress_window` seconds (Splunk-style throttling).
- **Severity from risk** — incident severity derived from accumulated risk and
  MITRE tactic position in the kill chain, not just the rule's static label.

**Exit criteria:** a scanning host that trips 4 rules produces **one** incident
with a risk score, not 4 separate alerts.

---

### Phase 6 — Detection Content, Intelligence & Response *(~4 weeks)*

**Goal:** scale detection content and close the loop to response.

- **Rule template library** — ship 30–50 curated, MITRE-mapped templates
  (CrowdStrike's model). Templates are parameterized; the builder offers
  "Start from template". Group by MITRE tactic and by data source.
- **MITRE gap → rule suggestion** — the coverage map already computes
  uncovered detectable techniques; make each uncovered cell a
  **"Create rule for this technique"** action that opens the builder
  pre-seeded with a relevant template. Closes the loop from the heat map.
- **Anomaly stages** — let a stage reference the existing learning-mode /
  anomaly baselines (`learning-mode` already exists in the platform) so a
  stage can be "volume anomalous vs baseline" rather than a static threshold.
  This is a pragmatic ML on-ramp without building a model from scratch.
- **Response actions on match** — wire matches/incidents to the existing
  notification service and (where available) policy/EDL actions:
  notify (email/Telegram/webhook), add source IP to a blocklist EDL,
  open a ticket. Make actions per-rule and per-severity.
- **Scheduled-rule contribution to Fusion-style detection** — allow ordinary
  alert rules (with MITRE tactics + entity mapping) to feed the risk engine,
  mirroring how Sentinel Fusion consumes scheduled analytics rules.

**Exit criteria:** an analyst can stand up a MITRE-gap-driven rule from a
template in <2 minutes, and a critical match can auto-contain.

---

## 7. New Feature Proposals (beyond parity)

Ideas that would differentiate Zentryc rather than just catch up:

1. **Attack-chain timeline visualization** — render a matched correlation as a
   horizontal kill-chain timeline (stage → stage → stage) with the actual
   events and timestamps, MITRE tactic per node. Most SIEMs show this as a
   table; a visual chain is a strong demo and analyst aid.
2. **"Explain this match"** — for any `correlation_matches` row, a one-click
   panel that shows exactly which events satisfied each stage and why,
   with log deep-links per stage. Builds analyst trust in the engine.
3. **Rule health / quality score** — per-rule scorecard: fire frequency,
   match-to-alert ratio, estimated false-positive rate (analyst feedback
   loop), last-tuned date. Surfaces "set-and-forget" rules that need
   attention — directly addresses the industry "living logic" best practice.
4. **Backtest against historical data** — run a draft or edited rule over the
   last 7/30 days of `correlation_matches`/`syslogs` and chart how often it
   *would* have fired. Stronger than a point-in-time preview.
5. **Sigma rule import** — Sigma is the de-facto open detection format; an
   importer that maps single-source Sigma rules into Zentryc stages would
   instantly multiply available content and ease migration from other SIEMs.
6. **Peer-group correlation** — "this host did X, which is rare among hosts in
   the same project/segment" — cheap behavioral analytics using existing
   `projects` / device grouping.
7. **Correlation simulation / purple-team mode** — inject synthetic event
   sequences to validate that rules fire, mapped to MITRE — turns the coverage
   map into a *tested* coverage map.

---

## 8. Prioritized Roadmap & Sequencing

| Phase | Theme | Effort | Priority | Depends on |
|-------|-------|--------|----------|------------|
| **1** | Correctness & hardening | ~1.5 wk | 🔴 P0 — do first | — |
| **2** | Visual rule builder + edit + test | ~3 wk | 🔴 P0 | Phase 1 (update API) |
| **3** | True sequencing & AND/OR/absence | ~4 wk | 🟠 P1 | Phase 1 |
| **4** | Multi-source correlation + entities | ~4 wk | 🟠 P1 | Phase 3 |
| **5** | Risk-based alerting & incidents | ~3 wk | 🟡 P2 | Phase 4 |
| **6** | Templates, ML stages, SOAR response | ~4 wk | 🟡 P2 | Phases 2 & 5 |

**Recommended cut for the next release (≈4.5 weeks): Phase 1 + Phase 2.**
This fixes every known defect and removes the single biggest adoption barrier
(raw-JSON authoring) — a clean, demoable milestone.

**Following release: Phase 3 + Phase 4** — the detection-credibility milestone.

**Then: Phase 5 + Phase 6** — the enterprise / differentiation milestone.

---

## 9. Technical Implementation Notes

### 9.1 Schema changes

`correlation_rules` (Alembic migration):
- `ordering VARCHAR(20) DEFAULT 'sequence'` — `sequence` | `any-order`
- `schema_version INT DEFAULT 2` — to migrate stage JSON shape safely
- `suppress_window INT DEFAULT 300` — per-rule throttling
- `actions JSON NULL` — response actions config
- Make `updated_at` actually used by the new update endpoint.

New ClickHouse tables:
- `entity_risk` — `entity_type, entity_value, score, rule_id, ts, decay_to`
- `correlation_incidents` (or reuse `Alert` with `parent_id`) for grouping.

### 9.2 Stage JSON v2 (illustrative)

```json
{
  "name": "Port Scan Detected",
  "source": "syslogs",
  "match": {
    "op": "AND",
    "conditions": [
      {"field": "action", "op": "eq", "value": "deny"}
    ]
  },
  "negate": false,
  "join_keys": ["srcip"],
  "group_by": "srcip",
  "threshold": 10,
  "window": 300
}
```

A converter migrates the 5 seeded v1 rules to v2 on deploy.

### 9.3 API surface (target)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/correlation/rules/` | list (exists) |
| POST | `/api/correlation/rules/` | create (exists — add validation) |
| **PUT** | `/api/correlation/rules/{id}` | **update (new)** |
| POST | `/api/correlation/rules/{id}/toggle` | toggle (exists) |
| DELETE | `/api/correlation/rules/{id}` | delete (exists) |
| **POST** | `/api/correlation/rules/{id}/clone` | **clone (new)** |
| **POST** | `/api/correlation/rules/test` | **dry-run preview (new)** |
| **POST** | `/api/correlation/rules/{id}/backtest` | **historical backtest (new)** |
| **GET** | `/api/correlation/schema` | **field catalog per source (new)** |
| **GET** | `/api/correlation/templates` | **template library (new)** |
| GET | `/api/correlation/rules/{id}/matches` | per-rule analytics (exists) |
| GET | `/api/correlation/matches/` | recent matches (exists) |

### 9.4 Performance

- Add a per-rule evaluation **watermark** (`last_event_ts` cursor) so each cycle
  only scans new events; persist in `correlation_rules` or `system_settings`.
- For high-volume rules, consider a ClickHouse **materialized view** that
  pre-aggregates `(srcip, action, minute) → count` so stage evaluation reads a
  small rollup instead of raw `syslogs`.
- Keep the singleton ClickHouse client (already fixed per project memory — do
  not regress the connection-leak fix).

### 9.5 Testing

- `tests/test_correlation.py` — unit-test `_build_where_clause` (incl. injection
  attempts), `_evaluate_stage`, temporal ordering, alert dedup boundary
  (minute 0–4), Pydantic stage validation.
- Integration test: seed events into a test ClickHouse, run
  `evaluate_correlation_rule`, assert match shape.

---

## 10. Success Metrics

Track before/after to prove the roadmap delivered value:

| Metric | Today (baseline) | Target after Phase 2 | Target after Phase 5 |
|--------|------------------|----------------------|----------------------|
| Time to author a new rule | ~10 min (hand-written JSON) | < 2 min (builder + template) | < 2 min |
| Rules created by non-admin analysts | 0 (ADMIN-only create) | analyst-authored drafts | — |
| Rule edits without delete/recreate | 0 (no edit path) | 100% | 100% |
| Stage temporal-ordering correctness | ❌ not enforced | ❌ (Phase 3) | ✅ enforced |
| Data sources correlatable | 1 | 1 | ≥ 6 |
| Alerts per real incident | 1:1 (flat) | 1:1 | many:1 (grouped) |
| MITRE detectable-technique coverage | 31% | 40%+ | 60%+ |
| Mean correlation false-positive rate | unknown (no feedback loop) | measured | measurably reduced |

---

## 11. Recommended Immediate Actions

1. **Triage Phase 1 bugs now** — §3.1 (temporal ordering) and §3.2 (alert
   `ValueError`) are correctness defects shipping in production today.
2. **Approve the Phase 1 + Phase 2 scope** as the next release — it is the
   cleanest, most demoable milestone and removes the biggest adoption blocker.
3. **Schedule a detection-engineering review** of the 5 seeded rules once
   temporal ordering lands — their thresholds were tuned against the *broken*
   semantics and will need re-baselining.
4. **Keep investing in the MITRE coverage map** — it is already a
   differentiator; Phase 6's gap→rule action turns it into a workflow.

---

## Appendix A — Competitive Sources

- Splunk Enterprise Security — Correlation Searches:
  [overview](https://help.splunk.com/en/splunk-enterprise-security-7/administer/7.3/correlation-searches/correlation-search-overview-for-splunk-enterprise-security),
  [configure](https://help.splunk.com/en/splunk-enterprise-security-7/administer/7.3/correlation-searches/configure-correlation-searches-in-splunk-enterprise-security),
  [create](https://help.splunk.com/en/splunk-enterprise-security-7/administer/7.3/correlation-searches/create-correlation-searches-in-splunk-enterprise-security)
- Microsoft Sentinel — Fusion / Advanced Multistage Attack Detection:
  [fusion](https://learn.microsoft.com/en-us/azure/sentinel/fusion),
  [configure Fusion rules](https://learn.microsoft.com/en-us/azure/sentinel/configure-fusion-rules),
  [threat detection](https://docs.azure.cn/en-us/sentinel/threat-detection)
- Elastic Security — Event Correlation (EQL) rules:
  [EQL rules](https://www.elastic.co/docs/solutions/security/detect-and-alert/eql),
  [detection-engineering capabilities](https://www.elastic.co/blog/elastic-security-detection-engineering)
- IBM QRadar — Rules, Building Blocks & Offense Chaining:
  [rules & building blocks](https://www.ibm.com/docs/en/qradar-common?topic=app-investigating-qradar-rules-building-blocks),
  [offense chaining](https://www.ibm.com/docs/en/SSKMKU/com.ibm.qradar.doc/c_qradar_ug_offense_chaining.html)
- CrowdStrike Falcon Next-Gen SIEM — Correlation Rule Template Discovery:
  [blog](https://www.crowdstrike.com/en-us/blog/boost-soc-detection-content-correlation-rule-template-discovery-dashboard/)
- Datadog Cloud SIEM — Signal Correlation Rules:
  [docs](https://docs.datadoghq.com/security/cloud_siem/detect_and_monitor/custom_detection_rules/signal_correlation_rules/)
- Industry best practice — SIEM correlation rules:
  [Stellar Cyber](https://stellarcyber.ai/learn/siem-correlation-rules/),
  [Cymulate — smarter SIEM alerts](https://cymulate.com/blog/smarter-siem-alerts-validation/)

## Appendix B — Files Reviewed

- `fastapi_app/models/correlation.py`
- `fastapi_app/services/correlation_engine.py`
- `fastapi_app/api/correlation.py`
- `fastapi_app/templates/correlation/rules.html`
- `fastapi_app/templates/correlation/mitre_map.html`
- `fastapi_app/services/scheduler.py` (job registration)
- `fastapi_app/main.py` (engine bootstrap)

Live review performed against `http://10.12.50.77/correlation/` and
`/correlation/mitre/` on 2026-05-20.
