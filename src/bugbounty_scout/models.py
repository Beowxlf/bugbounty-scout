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


class EndpointSource(BaseModel):
    type: str
    file: str = ""
    url: str = ""
    line: int | None = None
    evidence: str = ""
    redacted_evidence: str = ""


class Endpoint(BaseModel):
    id: str
    method: str = "UNKNOWN"
    scheme: str = ""
    host: str = ""
    path: str
    normalized_path: str
    url: str = ""
    query_params: list[str] = Field(default_factory=list)
    body_params: list[str] = Field(default_factory=list)
    json_keys: list[str] = Field(default_factory=list)
    header_names: list[str] = Field(default_factory=list)
    status_codes: list[int] = Field(default_factory=list)
    mime_types: list[str] = Field(default_factory=list)
    source: list[EndpointSource] = Field(default_factory=list)
    source_file: str = ""
    source_module: str = "endpoint-mapper"
    occurrences: int = 1
    risk_tags: list[str] = Field(default_factory=list)
    auth_indicators: list[str] = Field(default_factory=list)
    object_id_candidates: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)


class ApiInventory(BaseModel):
    project_name: str = "BugBountyScout passive inventory"
    endpoints: list[Endpoint] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=utc_now)
    source_files: list[str] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)


class TestingChecklistItem(BaseModel):
    endpoint_id: str
    category: str
    question: str
    reason: str
    priority: str


class FrontendFinding(BaseModel):
    id: str
    title: str
    type: str
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.MEDIUM
    asset: str
    source_file: str
    line: int | None = None
    column: int | None = None
    evidence: str = ""
    redacted_evidence: str = ""
    context: dict[str, Any] = Field(default_factory=dict)
    risk_tags: list[str] = Field(default_factory=list)
    recommendation: str = ""
    source_module: str = "frontend-exposure-analyzer"
    created_at: datetime = Field(default_factory=utc_now)


class SourceMapFinding(BaseModel):
    id: str
    source_map_file: str
    referenced_by: str = ""
    original_source_path: str = ""
    line: int | None = None
    evidence: str = ""
    redacted_evidence: str = ""
    finding_type: str
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.HIGH
    recommendation: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class ClientStorageReference(BaseModel):
    storage_type: str
    key: str = ""
    source_file: str
    line: int
    risk: str = "manual review"
    evidence: str = ""
    redacted_evidence: str = ""


class DomReviewLead(BaseModel):
    source_file: str
    line: int
    source_pattern: str
    sink_pattern: str
    evidence: str = ""
    redacted_evidence: str = ""
    review_reason: str


class PostMessageLead(BaseModel):
    source_file: str
    line: int
    pattern: str
    has_origin_check: bool
    evidence: str = ""
    redacted_evidence: str = ""
    review_reason: str


class FrontendInventory(BaseModel):
    project_name: str = "BugBountyScout frontend exposure inventory"
    source_files: list[str] = Field(default_factory=list)
    findings: list[FrontendFinding] = Field(default_factory=list)
    secrets: list[FrontendFinding] = Field(default_factory=list)
    runtime_configs: list[FrontendFinding] = Field(default_factory=list)
    source_maps: list[SourceMapFinding] = Field(default_factory=list)
    routes: list[Endpoint] = Field(default_factory=list)
    api_clients: list[FrontendFinding] = Field(default_factory=list)
    storage_references: list[ClientStorageReference] = Field(default_factory=list)
    dom_review_leads: list[DomReviewLead] = Field(default_factory=list)
    postmessage_leads: list[PostMessageLead] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=utc_now)
    summary: dict[str, Any] = Field(default_factory=dict)
