"""NQL parser / compiler tests (pure — no ClickHouse connection needed)."""
import pytest

from fastapi_app.services.nql_parser import (
    NQLSyntaxError, compile_nql, compile_filter, compose_nql,
    split_filter_and_pipeline, validate_nql,
)


def where(q):
    return compile_nql(q)["where"]


# ── filter expressions ─────────────────────────────────────────

def test_simple_indexed_equality():
    assert where("srcip:10.0.0.1") == "srcip = '10.0.0.1'"
    assert where("action:deny") == "action = 'deny'"


def test_boolean_precedence_and_parens():
    assert where("action:deny OR action:drop") == "(action = 'deny' OR action = 'drop')"
    # implicit AND binds tighter than OR
    assert where("srcip:1.1.1.1 OR srcip:2.2.2.2 action:deny") == \
        "(srcip = '1.1.1.1' OR (srcip = '2.2.2.2' AND action = 'deny'))"
    assert where("(srcip:1.1.1.1 OR srcip:2.2.2.2) action:deny") == \
        "((srcip = '1.1.1.1' OR srcip = '2.2.2.2') AND action = 'deny')"


def test_negation_forms():
    assert where("-action:allow") == "action != 'allow'"
    assert where("action:!=allow") == "action != 'allow'"
    assert where("NOT action:allow") == "NOT (action = 'allow')"
    assert where("NOT (action:deny OR action:drop)") == "NOT ((action = 'deny' OR action = 'drop'))"


def test_quoted_values_with_spaces_and_pipes():
    assert where('policyname:"Allow Web Traffic"') == "policyname = 'Allow Web Traffic'"
    assert where('msg:~"a | b"') == "parsed_data['msg'] ILIKE '%a | b%'"


def test_ip_shapes():
    assert where("srcip:10.0.0.0/8") == "startsWith(srcip, '10.')"
    assert "srcip_v4" in where("srcip:10.0.0.0/12")
    assert where("dstip:192.168.1.*") == "dstip LIKE '192.168.1.%'"
    assert where("srcip:1.2.3.4,5.6.7.8") == "(srcip = '1.2.3.4' OR srcip = '5.6.7.8')"


def test_numeric_and_range_operators():
    assert where("dstport:>1024") == "dstport > 1024"
    assert where("dstport:80-443") == "(dstport >= 80 AND dstport <= 443)"
    assert where("sent_bytes:>=1000000") == "sent_bytes >= 1000000"
    assert where("proto:6|17") == "(proto = 6 OR proto = 17)"


def test_free_text_and_parsed_data_fields():
    assert where("timeout") == "(message ILIKE '%timeout%' OR raw ILIKE '%timeout%')"
    assert where("appcat:~video").startswith("if(parsed_data['appcat']")
    assert where("unknownfield:xyz") == "lower(parsed_data['unknownfield']) = lower('xyz')"


def test_sql_injection_is_escaped():
    w = where("policyname:\"x' OR 1=1 --\"")
    assert w == "policyname = 'x'' OR 1=1 --'"
    with pytest.raises(NQLSyntaxError):
        compile_nql("action:deny | sort srcip)/**/UNION/**/SELECT")


# ── error messages ─────────────────────────────────────────────

@pytest.mark.parametrize("q,fragment", [
    ("action:", "Missing value"),
    ("dstport:>=", "Missing value"),
    ("srcip:10.0.0.1 AND", "after AND"),
    ("OR action:deny", "both sides"),
    ("(action:deny", "closing"),
    ("action:deny)", "Unmatched"),
    ("()", "Empty parentheses"),
    ("action:deny | foo", "Unknown pipeline command"),
    ("action:deny |", "Expected a pipeline command"),
    ("action:deny | stats count by srcip | sort -dstip", "Cannot sort"),
    ("action:deny | where count > x", "numeric"),
])
def test_syntax_errors_are_explained(q, fragment):
    ok, err = validate_nql(q)
    assert not ok
    assert fragment in err, err


# ── pipeline ───────────────────────────────────────────────────

def test_stats_pipeline():
    c = compile_nql("action:deny | stats count by srcip | where count > 100 | sort -count | limit 20")
    assert c["is_aggregate"]
    assert c["where"] == "action = 'deny'"
    assert c["select"] == "srcip, count() as count"
    assert c["group_by"] == "srcip"
    assert c["having"] == "count > 100"
    assert c["order_by"] == "count DESC"
    assert c["limit"] == 20


def test_stats_on_parsed_data_field_and_alias():
    c = compile_nql("| stats sum(sent_bytes) as bytes by srccountry, appcat")
    assert c["is_aggregate"]
    assert "sum(sent_bytes) as bytes" in c["select"]
    assert "AS srccountry" in c["select"] and "AS appcat" in c["select"]
    assert c["group_by"] == "srccountry, appcat"


def test_value_or_pipe_is_not_a_pipeline_pipe():
    f, p = split_filter_and_pipeline("action:deny|drop | stats count by srcip")
    assert f == "action:deny|drop"
    assert p == "stats count by srcip"


def test_log_sort_and_limit():
    c = compile_nql("action:deny | sort -dstport | limit 50")
    assert not c["is_aggregate"]
    assert c["order_by"] == "dstport DESC"
    assert c["limit"] == 50


# ── helpers used by the explorer ───────────────────────────────

def test_compose_preserves_or_precedence_and_pipeline():
    assert compose_nql("srcip:a OR srcip:b | stats count by srcip", ["action:deny"]) == \
        "(srcip:a OR srcip:b) action:deny | stats count by srcip"
    assert compose_nql("", ["action:deny"]) == "action:deny"
    assert compose_nql("| stats count by srcip", ["action:deny"]) == "action:deny | stats count by srcip"
    assert compose_nql("timeout", []) == "timeout"


def test_compile_filter_ignores_pipeline_and_extracts_cheap_prewhere():
    w, pw = compile_filter("(srcip:10.0.0.0/8 OR srcip:192.168.0.0/16) action:deny appcat:~video timeout -dstport:443 | stats count by srcip")
    assert "count()" not in w
    assert set(pw) == {"(startsWith(srcip, '10.') OR startsWith(srcip, '192.168.'))",
                       "action = 'deny'", "dstport != 443"}
    # heavy columns never reach PREWHERE
    assert not any("parsed_data" in c or "message" in c for c in pw)


def test_compile_filter_empty():
    assert compile_filter("") == ("1=1", ())
    assert compile_filter("| stats count by srcip") == ("1=1", ())


def test_stats_rejects_partially_parsed_clause():
    ok, err = validate_nql("| stats sum(sent_bytes) as bytes, by src_country")
    assert not ok and "Invalid stats syntax" in err
    c = compile_nql("| stats sum(sent_bytes) as total")
    assert c["select"] == "sum(sent_bytes) as total"
