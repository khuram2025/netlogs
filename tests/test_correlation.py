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

from fastapi_app.core.correlation_fields import parse_field_op
from fastapi_app.services.correlation_engine import (
    StageEvalError,
    _build_where_clause,
    _recent_alert_cutoff,
    _resolve_variable,
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
