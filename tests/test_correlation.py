"""
Unit tests for the Phase 0 correlation engine hardening.

Covers:
- parse_field_op          — field/operator splitting
- _resolve_variable       — $stageN.field resolution, fail-closed (P0-8)
- _build_where_clause     — allow-list, parameter binding, injection rejection
                            (P0-3 / P0-4 / P0-5 / P0-8)
- _recent_alert_cutoff    — P0-1 regression (no ValueError near the hour edge)
- StageSchema /           — P0-6 / P0-7 save-time validation
  CorrelationRuleCreate
- compute_coverage_stats  — P0-2 MITRE coverage can never exceed 100%
"""

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

import types

from fastapi_app.core.correlation_fields import parse_field_op
from fastapi_app.services.correlation_engine import (
    StageEvalError,
    _as_list,
    _build_where_clause,
    _entity_type_for_field,
    _entity_where,
    _recent_alert_cutoff,
    _resolve_variable,
    _rule_join_keys,
    _safe_int,
    _stage_time_filter,
    match_fingerprint,
    preview_correlation_rule,
)
from fastapi_app.schemas.correlation import (
    CorrelationRuleCreate,
    CorrelationRuleUpdate,
    StageSchema,
)
from fastapi_app.api.correlation import compute_coverage_stats


# ----------------------------------------------------------------------
# parse_field_op
# ----------------------------------------------------------------------

class TestParseFieldOp:
    def test_plain_field_is_equality(self):
        assert parse_field_op("action") == ("action", "=")

    def test_gt_suffix(self):
        assert parse_field_op("dstport_gt") == ("dstport", ">")

    def test_gte_suffix_not_confused_with_gt(self):
        assert parse_field_op("dstport_gte") == ("dstport", ">=")

    def test_lte_suffix(self):
        assert parse_field_op("severity_lte") == ("severity", "<=")

    def test_ne_suffix(self):
        assert parse_field_op("action_ne") == ("action", "!=")

    def test_bare_suffix_not_treated_as_operator(self):
        # "_gt" with no field name in front stays a plain field
        assert parse_field_op("_gt") == ("_gt", "=")


# ----------------------------------------------------------------------
# _resolve_variable  (P0-8 fail-closed)
# ----------------------------------------------------------------------

class TestResolveVariable:
    def test_resolves_from_prior_stage(self):
        value, optional = _resolve_variable("$stage1.srcip", {"stage1": {"srcip": "10.0.0.5"}})
        assert value == "10.0.0.5"
        assert optional is False

    def test_required_unresolved_raises(self):
        with pytest.raises(StageEvalError):
            _resolve_variable("$stage1.srcip", {})

    def test_required_unresolved_with_no_variables_raises(self):
        with pytest.raises(StageEvalError):
            _resolve_variable("$stage1.dstip", None)

    def test_optional_unresolved_returns_none(self):
        value, optional = _resolve_variable("$stage1.srcip?", {})
        assert value is None
        assert optional is True

    def test_optional_resolved_returns_value(self):
        value, optional = _resolve_variable("$stage1.dstip?", {"stage1": {"dstip": "8.8.8.8"}})
        assert value == "8.8.8.8"
        assert optional is True


# ----------------------------------------------------------------------
# _build_where_clause  (P0-3 / P0-4 / P0-5 / P0-8)
# ----------------------------------------------------------------------

class TestBuildWhereClause:
    def test_simple_equality_is_parameterized(self):
        where, params = _build_where_clause({"action": "deny"})
        assert where == "action = {p0:String}"
        assert params == {"p0": "deny"}
        # the value must never be inlined into the SQL text
        assert "deny" not in where

    def test_numeric_field_uses_float_param(self):
        where, params = _build_where_clause({"dstport_gt": 1024})
        assert where == "dstport > {p0:Float64}"
        assert params == {"p0": 1024.0}

    def test_ne_operator(self):
        where, params = _build_where_clause({"action_ne": "allow"})
        assert where == "action != {p0:String}"
        assert params == {"p0": "allow"}

    def test_unknown_field_rejected(self):
        with pytest.raises(StageEvalError):
            _build_where_clause({"totally_not_a_column": "x"})

    def test_sql_injection_in_field_name_rejected(self):
        # a crafted field name is not in the allow-list -> cannot reach SQL
        with pytest.raises(StageEvalError):
            _build_where_clause({"srcip = '' OR 1=1 --": "x"})

    def test_sql_injection_in_value_is_bound_not_inlined(self):
        payload = "deny'; DROP TABLE syslogs; --"
        where, params = _build_where_clause({"action": payload})
        assert payload not in where          # not concatenated into SQL
        assert params["p0"] == payload       # safely bound as a parameter

    def test_numeric_operator_on_string_field_rejected(self):
        with pytest.raises(StageEvalError):
            _build_where_clause({"action_gt": "deny"})

    def test_non_numeric_value_for_numeric_field_rejected(self):
        with pytest.raises(StageEvalError):
            _build_where_clause({"dstport": "not-a-number"})

    def test_variable_substitution_is_parameterized(self):
        where, params = _build_where_clause(
            {"action": "allow", "srcip": "$stage1.srcip"},
            {"stage1": {"srcip": "10.1.2.3"}},
        )
        assert params["p0"] == "allow"
        assert params["p1"] == "10.1.2.3"
        assert "10.1.2.3" not in where

    def test_required_variable_unresolved_fails_closed(self):
        # P0-8: must NOT silently drop the join condition
        with pytest.raises(StageEvalError):
            _build_where_clause({"action": "allow", "srcip": "$stage1.srcip"}, {})

    def test_optional_variable_unresolved_is_skipped(self):
        where, params = _build_where_clause(
            {"action": "allow", "srcip": "$stage1.srcip?"}, {}
        )
        assert where == "action = {p0:String}"
        assert params == {"p0": "allow"}

    def test_group_by_threshold_window_keys_ignored(self):
        where, params = _build_where_clause(
            {"action": "deny", "group_by": "srcip", "threshold": 10, "window": 300}
        )
        assert where == "action = {p0:String}"

    def test_empty_filter_yields_true(self):
        where, params = _build_where_clause({})
        assert where == "1=1"
        assert params == {}

    def test_unknown_source_rejected(self):
        with pytest.raises(StageEvalError):
            _build_where_clause({"action": "deny"}, source="nonexistent")


# ----------------------------------------------------------------------
# _recent_alert_cutoff  (P0-1 regression)
# ----------------------------------------------------------------------

class TestRecentAlertCutoff:
    def test_returns_five_minutes_ago(self):
        before = datetime.now(timezone.utc) - timedelta(minutes=5)
        cutoff = _recent_alert_cutoff()
        after = datetime.now(timezone.utc) - timedelta(minutes=5)
        assert before <= cutoff <= after

    def test_is_timezone_aware(self):
        assert _recent_alert_cutoff().tzinfo is not None

    def test_custom_window(self):
        delta = datetime.now(timezone.utc) - _recent_alert_cutoff(minutes=15)
        assert timedelta(minutes=14) < delta < timedelta(minutes=16)


# ----------------------------------------------------------------------
# StageSchema / CorrelationRuleCreate  (P0-6 / P0-7)
# ----------------------------------------------------------------------

VALID_STAGE = {
    "name": "Port Scan",
    "filter": {"action": "deny", "group_by": "srcip"},
    "threshold": 10,
    "window": 300,
}


class TestStageSchema:
    def test_valid_stage(self):
        stage = StageSchema(**VALID_STAGE)
        assert stage.name == "Port Scan"
        assert stage.source == "syslogs"

    def test_unknown_filter_field_rejected(self):
        with pytest.raises(ValidationError):
            StageSchema(name="x", filter={"bogus_field": "y"})

    def test_unknown_group_by_rejected(self):
        with pytest.raises(ValidationError):
            StageSchema(name="x", filter={"action": "deny", "group_by": "bogus"})

    def test_numeric_op_on_string_field_rejected(self):
        with pytest.raises(ValidationError):
            StageSchema(name="x", filter={"action_gt": "deny"})

    def test_non_numeric_value_for_numeric_field_rejected(self):
        with pytest.raises(ValidationError):
            StageSchema(name="x", filter={"dstport": "abc"})

    def test_threshold_must_be_positive(self):
        with pytest.raises(ValidationError):
            StageSchema(name="x", filter={"action": "deny"}, threshold=0)

    def test_window_upper_bound(self):
        with pytest.raises(ValidationError):
            StageSchema(name="x", filter={"action": "deny"}, window=999_999_999)

    def test_unknown_source_rejected(self):
        with pytest.raises(ValidationError):
            StageSchema(name="x", source="splunk", filter={"action": "deny"})

    def test_variable_value_skips_type_check(self):
        stage = StageSchema(name="x", filter={"srcip": "$stage1.srcip"})
        assert stage.filter["srcip"] == "$stage1.srcip"


class TestCorrelationRuleCreate:
    def test_valid_rule(self):
        rule = CorrelationRuleCreate(name="Test Rule", stages=[VALID_STAGE])
        assert rule.severity == "high"
        assert rule.is_enabled is True
        assert len(rule.stages) == 1

    def test_empty_stages_rejected(self):
        with pytest.raises(ValidationError):
            CorrelationRuleCreate(name="Test", stages=[])

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValidationError):
            CorrelationRuleCreate(name="Test", severity="apocalyptic", stages=[VALID_STAGE])

    def test_blank_name_rejected(self):
        with pytest.raises(ValidationError):
            CorrelationRuleCreate(name="", stages=[VALID_STAGE])

    def test_too_many_stages_rejected(self):
        with pytest.raises(ValidationError):
            CorrelationRuleCreate(name="Test", stages=[VALID_STAGE] * 11)

    def test_malformed_stage_rejected(self):
        with pytest.raises(ValidationError):
            CorrelationRuleCreate(name="Test", stages=[{"name": "s", "filter": {"bad": "v"}}])


class TestCorrelationRuleUpdate:
    def test_partial_update_allowed(self):
        upd = CorrelationRuleUpdate(severity="critical")
        assert upd.model_dump(exclude_unset=True) == {"severity": "critical"}

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValidationError):
            CorrelationRuleUpdate(severity="bogus")

    def test_invalid_stage_in_update_rejected(self):
        with pytest.raises(ValidationError):
            CorrelationRuleUpdate(stages=[{"name": "x", "filter": {"bad": "y"}}])

    def test_empty_update_is_valid(self):
        # an empty update validates; the endpoint rejects "no fields" separately
        assert CorrelationRuleUpdate().model_dump(exclude_unset=True) == {}


# ----------------------------------------------------------------------
# compute_coverage_stats  (P0-2)
# ----------------------------------------------------------------------

class TestComputeCoverageStats:
    def test_empty_coverage_is_zero_percent(self):
        stats, total, covered, detectable, pct = compute_coverage_stats({})
        assert covered == 0
        assert pct == 0
        assert total > 0          # the technique catalog is non-empty
        assert detectable > 0

    def test_pct_never_exceeds_100_with_all_techniques_mapped(self):
        # Map EVERY technique id, including non-detectable ones. The old bug
        # counted those in the numerator over a detectable-only denominator,
        # inflating the percentage past 100. The fix keeps covered a subset
        # of detectable.
        from fastapi_app.core.mitre_attack import TECHNIQUES
        all_ids = {}
        for techs in TECHNIQUES.values():
            for t in techs:
                all_ids[t["id"].split(" ")[0]] = [{"name": "x"}]
        stats, total, covered, detectable, pct = compute_coverage_stats(all_ids)
        assert covered <= detectable
        assert pct <= 100
        for tactic in stats:
            assert tactic["covered"] <= tactic["detectable"]
            assert tactic["pct"] <= 100

    def test_covered_is_subset_of_detectable(self):
        stats, total, covered, detectable, pct = compute_coverage_stats(
            {"T1595": [{"name": "scan rule"}]}
        )
        assert 0 <= covered <= detectable


# ======================================================================
# PHASE 1 — Match identity, fingerprint, suppression
# ======================================================================

# ----------------------------------------------------------------------
# match_fingerprint  (P1-2)
# ----------------------------------------------------------------------

class TestMatchFingerprint:
    def test_is_deterministic(self):
        a = match_fingerprint(1, 1, "ip", "10.0.0.5")
        b = match_fingerprint(1, 1, "ip", "10.0.0.5")
        assert a == b

    def test_is_a_sha1_hex_digest(self):
        fp = match_fingerprint(1, 1, "ip", "10.0.0.5")
        assert len(fp) == 40
        int(fp, 16)  # must be valid hex

    def test_different_entity_differs(self):
        assert match_fingerprint(1, 1, "ip", "10.0.0.5") != \
               match_fingerprint(1, 1, "ip", "10.0.0.6")

    def test_different_rule_differs(self):
        assert match_fingerprint(1, 1, "ip", "10.0.0.5") != \
               match_fingerprint(2, 1, "ip", "10.0.0.5")

    def test_different_version_differs(self):
        # a rule edit (version bump) must reset the fingerprint so
        # suppression does not carry across rule definitions
        assert match_fingerprint(1, 1, "ip", "10.0.0.5") != \
               match_fingerprint(1, 2, "ip", "10.0.0.5")

    def test_different_entity_type_differs(self):
        assert match_fingerprint(1, 1, "ip", "x") != \
               match_fingerprint(1, 1, "user", "x")


# ----------------------------------------------------------------------
# _entity_type_for_field  (P1-1)
# ----------------------------------------------------------------------

class TestEntityTypeForField:
    def test_ip_fields(self):
        assert _entity_type_for_field("srcip") == "ip"
        assert _entity_type_for_field("dstip") == "ip"
        assert _entity_type_for_field("device_ip") == "ip"

    def test_unknown_field_returns_field_name(self):
        assert _entity_type_for_field("policyname") == "policyname"

    def test_none_returns_none_literal(self):
        assert _entity_type_for_field(None) == "none"
        assert _entity_type_for_field("") == "none"


# ----------------------------------------------------------------------
# Phase 1 schema fields — match_mode / suppress_window  (P1-4 / P1-6)
# ----------------------------------------------------------------------

class TestPhase1RuleSchema:
    def test_defaults_are_discrete_and_one_hour(self):
        rule = CorrelationRuleCreate(name="R", stages=[VALID_STAGE])
        assert rule.match_mode == "discrete"
        assert rule.suppress_window == 3600

    def test_recurring_mode_accepted(self):
        rule = CorrelationRuleCreate(name="R", stages=[VALID_STAGE], match_mode="recurring")
        assert rule.match_mode == "recurring"

    def test_invalid_mode_rejected(self):
        with pytest.raises(ValidationError):
            CorrelationRuleCreate(name="R", stages=[VALID_STAGE], match_mode="sometimes")

    def test_suppress_window_lower_bound(self):
        with pytest.raises(ValidationError):
            CorrelationRuleCreate(name="R", stages=[VALID_STAGE], suppress_window=10)

    def test_suppress_window_upper_bound(self):
        with pytest.raises(ValidationError):
            CorrelationRuleCreate(name="R", stages=[VALID_STAGE], suppress_window=999_999_999)

    def test_update_accepts_mode_and_window(self):
        upd = CorrelationRuleUpdate(match_mode="recurring", suppress_window=7200)
        data = upd.model_dump(exclude_unset=True)
        assert data == {"match_mode": "recurring", "suppress_window": 7200}


# ======================================================================
# PHASE 2 — True sequence engine
# ======================================================================

# ----------------------------------------------------------------------
# _as_list / _safe_int
# ----------------------------------------------------------------------

class TestAsList:
    def test_none_and_empty(self):
        assert _as_list(None) == []
        assert _as_list("") == []

    def test_scalar_wrapped(self):
        assert _as_list("srcip") == ["srcip"]

    def test_list_passthrough(self):
        assert _as_list(["srcip", "dstip"]) == ["srcip", "dstip"]


class TestSafeInt:
    def test_valid(self):
        assert _safe_int("300", "window") == 300
        assert _safe_int(10, "threshold") == 10

    def test_invalid_raises(self):
        with pytest.raises(StageEvalError):
            _safe_int("not-a-number", "window")


# ----------------------------------------------------------------------
# _stage_time_filter  (P2-3 / P2-4 — temporal anchoring)
# ----------------------------------------------------------------------

class TestStageTimeFilter:
    def test_trailing_window_without_anchor(self):
        sql, params = _stage_time_filter(300, anchor=None)
        assert sql == "timestamp > now() - INTERVAL 300 SECOND"
        assert params == {}

    def test_anchored_window_for_sequence(self):
        anchor = datetime(2026, 5, 20, 12, 0, 0)
        sql, params = _stage_time_filter(600, anchor=anchor)
        # anchored window proves stage B follows stage A
        assert "timestamp > {_anchor:DateTime64(3)}" in sql
        assert "+ INTERVAL 600 SECOND" in sql
        assert params == {"_anchor": anchor}

    def test_bad_window_raises(self):
        with pytest.raises(StageEvalError):
            _stage_time_filter("xyz")


# ----------------------------------------------------------------------
# _entity_where  (P2-6 / P2-7 — first-class joins)
# ----------------------------------------------------------------------

class TestEntityWhere:
    def test_single_string_field(self):
        sql, params = _entity_where({"srcip": "10.0.0.5"}, "syslogs")
        assert sql == "srcip = {e0:String}"
        assert params == {"e0": "10.0.0.5"}

    def test_numeric_field_binds_float(self):
        sql, params = _entity_where({"dstport": 443}, "syslogs")
        assert sql == "dstport = {e0:Float64}"
        assert params == {"e0": 443.0}

    def test_ip_field_wrapped(self):
        sql, params = _entity_where({"device_ip": "10.1.1.1"}, "syslogs")
        assert "toIPv4({e0:String})" in sql

    def test_composite_join(self):
        sql, params = _entity_where({"srcip": "10.0.0.5", "dstip": "8.8.8.8"}, "syslogs")
        assert sql == "srcip = {e0:String} AND dstip = {e1:String}"
        assert params == {"e0": "10.0.0.5", "e1": "8.8.8.8"}

    def test_empty_entity_is_true(self):
        sql, params = _entity_where({}, "syslogs")
        assert sql == "1=1"
        assert params == {}


# ----------------------------------------------------------------------
# _rule_join_keys
# ----------------------------------------------------------------------

class TestRuleJoinKeys:
    def test_explicit_join_keys_win(self):
        rule = types.SimpleNamespace(join_keys=["srcip", "dstip"])
        stages = [{"filter": {"group_by": "policyname"}}]
        assert _rule_join_keys(rule, stages) == ["srcip", "dstip"]

    def test_falls_back_to_stage1_group_by(self):
        rule = types.SimpleNamespace(join_keys=None)
        stages = [{"filter": {"action": "deny", "group_by": "srcip"}}]
        assert _rule_join_keys(rule, stages) == ["srcip"]

    def test_no_join_keys_and_no_group_by(self):
        rule = types.SimpleNamespace(join_keys=None)
        stages = [{"filter": {"action": "deny"}}]
        assert _rule_join_keys(rule, stages) == []


# ----------------------------------------------------------------------
# Phase 2 schema — ordering / join_keys  (P2-1 / P2-2)
# ----------------------------------------------------------------------

class TestPhase2RuleSchema:
    def test_ordering_defaults_to_sequence(self):
        rule = CorrelationRuleCreate(name="R", stages=[VALID_STAGE])
        assert rule.ordering == "sequence"

    def test_any_order_accepted(self):
        rule = CorrelationRuleCreate(name="R", stages=[VALID_STAGE], ordering="any_order")
        assert rule.ordering == "any_order"

    def test_invalid_ordering_rejected(self):
        with pytest.raises(ValidationError):
            CorrelationRuleCreate(name="R", stages=[VALID_STAGE], ordering="backwards")

    def test_valid_join_keys_accepted(self):
        rule = CorrelationRuleCreate(name="R", stages=[VALID_STAGE],
                                     join_keys=["srcip", "dstip"])
        assert rule.join_keys == ["srcip", "dstip"]

    def test_invalid_join_key_rejected(self):
        with pytest.raises(ValidationError):
            CorrelationRuleCreate(name="R", stages=[VALID_STAGE], join_keys=["not_a_field"])

    def test_composite_match_fingerprint(self):
        # composite entity values are joined with "|"
        fp1 = match_fingerprint(1, 1, "composite", "10.0.0.5|8.8.8.8")
        fp2 = match_fingerprint(1, 1, "composite", "10.0.0.5|8.8.8.9")
        assert fp1 != fp2


# ======================================================================
# PHASE 3 — preview / dry-run
# ======================================================================

class TestPreviewCorrelationRule:
    """preview_correlation_rule must dry-run without persisting and return a
    stable diagnostic shape. (Stage execution itself needs ClickHouse and is
    covered by integration verification.)"""

    def test_no_stages_returns_error(self):
        rule = types.SimpleNamespace(stages=[], name="Empty", ordering="sequence")
        d = preview_correlation_rule(rule)
        assert d["ok"] is False
        assert d["error"] == "Rule has no stages."
        assert d["matched_chains"] == 0

    def test_none_stages_returns_error(self):
        rule = types.SimpleNamespace(stages=None, name="Empty", ordering="sequence")
        d = preview_correlation_rule(rule)
        assert d["ok"] is False
        assert d["error"]

    def test_diag_has_expected_keys(self):
        rule = types.SimpleNamespace(stages=[], name="x", ordering="sequence")
        d = preview_correlation_rule(rule)
        for key in ("ok", "matched_chains", "stages", "sample_matches",
                    "estimated_per_hour", "error"):
            assert key in d
