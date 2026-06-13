"""Shared validated data models."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class Finding(BaseModel):
    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    type: str = Field(min_length=1)
    severity: Severity
    confidence: Confidence
    asset: str = Field(min_length=1)
    evidence: str = ""
    redacted_evidence: str = ""
    impact: str = ""
    recommendation: str = ""
    source_module: str = Field(min_length=1)
    location: str = ""
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("id", "title", "type", "asset", "source_module")
    @classmethod
    def non_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value.strip()


class EvidenceItem(BaseModel):
    id: str = Field(min_length=1)
    type: str = Field(min_length=1)
    path: str = Field(min_length=1)
    description: str = ""
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    redacted: bool = True
    created_at: datetime = Field(default_factory=utc_now)


class ScopeProfile(BaseModel):
    program_name: str = Field(min_length=1)
    platform: str = ""
    in_scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    forbidden_tests: list[str] = Field(default_factory=list)
    rate_limits: dict[str, Any] = Field(default_factory=dict)
    auth_notes: str = ""
    report_notes: str = ""


class ScopeDecision(BaseModel):
    url: str
    allowed: bool
    reason: str
    matched_rule: str | None = None
