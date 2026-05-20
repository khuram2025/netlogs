"""
Pydantic schemas for correlation rule create / update requests.

Phase 0 hardening: malformed correlation rules are rejected at save time with a
user-readable validation error, instead of being stored verbatim and then
failing silently at scheduler-evaluation time.
"""

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from ..core.correlation_fields import (
    DEFAULT_SOURCE,
    NON_FIELD_FILTER_KEYS,
    NUMERIC_ONLY_OPERATORS,
    get_source_fields,
    is_valid_source,
    parse_field_op,
)

Severity = Literal["critical", "high", "medium", "low"]
MatchOrdering = Literal["sequence", "any_order"]


def _is_number(value: Any) -> bool:
    try:
        float(value)
        return True
    except (TypeError, ValueError):
        return False


class StageSchema(BaseModel):
    """One stage of a multi-stage correlation rule."""

    name: str = Field(..., min_length=1, max_length=200)
    source: str = Field(default=DEFAULT_SOURCE, max_length=50)
    filter: Dict[str, Any] = Field(default_factory=dict)
    threshold: int = Field(default=1, ge=1, le=100_000_000)
    window: int = Field(default=300, ge=1, le=604_800)  # 1 second .. 7 days
    group_by: Optional[str] = Field(default=None, max_length=100)

    @model_validator(mode="after")
    def _validate_stage(self):
        if not is_valid_source(self.source):
            raise ValueError(f"Unknown data source '{self.source}'")
        fields = get_source_fields(self.source)

        # group_by may be given at the top level or inside the filter dict.
        gb = self.filter.get("group_by", self.group_by)
        if gb is not None and gb not in fields:
            raise ValueError(
                f"group_by field '{gb}' is not valid for source '{self.source}'"
            )

        for key, value in self.filter.items():
            if key in NON_FIELD_FILTER_KEYS:
                continue
            actual_field, op = parse_field_op(key)
            if actual_field not in fields:
                raise ValueError(
                    f"filter field '{actual_field}' is not valid for source '{self.source}'"
                )
            ftype = fields[actual_field]
            if op in NUMERIC_ONLY_OPERATORS and ftype != "numeric":
                raise ValueError(
                    f"operator on '{key}' requires a numeric field"
                )
            # $stageN.field variable references are resolved at evaluation time.
            if isinstance(value, str) and value.startswith("$"):
                continue
            if ftype == "numeric" and not _is_number(value):
                raise ValueError(f"filter '{key}' requires a numeric value")
        return self


MatchMode = Literal["discrete", "recurring"]


class CorrelationRuleCreate(BaseModel):
    """Payload for creating a correlation rule."""

    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(default="", max_length=2000)
    severity: Severity = "high"
    is_enabled: bool = True
    stages: List[StageSchema] = Field(..., min_length=1, max_length=10)
    mitre_tactic: Optional[str] = Field(default=None, max_length=100)
    mitre_technique: Optional[str] = Field(default=None, max_length=100)
    # Phase 1: match identity / suppression
    match_mode: MatchMode = "discrete"
    suppress_window: int = Field(default=3600, ge=60, le=604_800)
    # Phase 2: stage ordering / join
    ordering: MatchOrdering = "sequence"
    join_keys: Optional[List[str]] = Field(default=None, max_length=4)

    @field_validator("join_keys")
    @classmethod
    def _check_join_keys(cls, v):
        if v:
            fields = get_source_fields(DEFAULT_SOURCE) or {}
            for key in v:
                if key not in fields:
                    raise ValueError(f"join key '{key}' is not a valid field")
        return v


class CorrelationRuleUpdate(BaseModel):
    """Payload for updating a correlation rule — only provided fields change."""

    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=2000)
    severity: Optional[Severity] = None
    is_enabled: Optional[bool] = None
    stages: Optional[List[StageSchema]] = Field(default=None, min_length=1, max_length=10)
    mitre_tactic: Optional[str] = Field(default=None, max_length=100)
    mitre_technique: Optional[str] = Field(default=None, max_length=100)
    match_mode: Optional[MatchMode] = None
    suppress_window: Optional[int] = Field(default=None, ge=60, le=604_800)
    ordering: Optional[MatchOrdering] = None
    join_keys: Optional[List[str]] = Field(default=None, max_length=4)

    @field_validator("join_keys")
    @classmethod
    def _check_join_keys(cls, v):
        if v:
            fields = get_source_fields(DEFAULT_SOURCE) or {}
            for key in v:
                if key not in fields:
                    raise ValueError(f"join key '{key}' is not a valid field")
        return v
