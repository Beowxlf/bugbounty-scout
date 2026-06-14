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


class EvidenceType(StrEnum):
    RAW_REQUEST = "raw_request"
    RAW_RESPONSE = "raw_response"
    REDACTED_REQUEST = "redacted_request"
    REDACTED_RESPONSE = "redacted_response"
    SCREENSHOT = "screenshot"
    HAR_ENTRY = "har_entry"
    SOURCE_FILE = "source_file"
    SOURCE_MAP = "source_map"
    AUTHZ_MATRIX = "authz_matrix"
    ENDPOINT_INVENTORY = "endpoint_inventory"
    FRONTEND_INVENTORY = "frontend_inventory"
    NOTE = "note"
    COMMAND_OUTPUT = "command_output"
    OTHER = "other"


class EvidenceStatus(StrEnum):
    DRAFT = "draft"
    NEEDS_REVIEW = "needs_review"
    READY = "ready"
    SUBMITTED = "submitted"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"
    INFORMATIONAL = "informational"


class QualityWarningCategory(StrEnum):
    MISSING_IMPACT = "missing_impact"
    MISSING_EVIDENCE = "missing_evidence"
    MISSING_REPRODUCTION_STEPS = "missing_reproduction_steps"
    MISSING_AFFECTED_ASSET = "missing_affected_asset"
    MISSING_EXPECTED_ACTUAL = "missing_expected_actual"
    WEAK_LANGUAGE = "weak_language"
    UNSUPPORTED_SEVERITY = "unsupported_severity"
    UNREDACTED_SECRET = "unredacted_secret"
    UNREDACTED_COOKIE = "unredacted_cookie"
    UNREDACTED_TOKEN = "unredacted_token"
    PII_EXPOSURE = "pii_exposure"
    VAGUE_TITLE = "vague_title"
    NO_REMEDIATION = "no_remediation"
    NO_SCOPE_NOTES = "no_scope_notes"
    NEEDS_MANUAL_VALIDATION = "needs_manual_validation"


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
    type: EvidenceType
    title: str = ""
    description: str = ""
    path: str = ""
    sha256: str = Field(default="", pattern=r"^$|^[a-fA-F0-9]{64}$")
    source_module: str = "evidence-locker"
    redacted: bool = True
    contains_sensitive_data: bool = False
    evidence_text: str = ""
    redacted_evidence_text: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class ReproductionStep(BaseModel):
    id: str = Field(min_length=1)
    order: int = Field(ge=1)
    action: str = Field(min_length=1)
    expected_result: str = ""
    actual_result: str = ""
    evidence_reference: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class ReportQualityWarning(BaseModel):
    id: str = Field(min_length=1)
    category: QualityWarningCategory
    severity: Severity = Severity.INFO
    message: str = Field(min_length=1)
    recommendation: str = ""
    field: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class EvidenceWorkspace(BaseModel):
    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    finding_type: str = ""
    affected_assets: list[str] = Field(default_factory=list)
    severity_estimate: Severity = Severity.INFO
    confidence: Confidence = Confidence.MEDIUM
    status: EvidenceStatus = EvidenceStatus.DRAFT
    tags: list[str] = Field(default_factory=list)
    scope_notes: str = ""
    actor_context: str = ""
    object_context: str = ""
    expected_behavior: str = ""
    actual_behavior: str = ""
    impact: str = ""
    severity_rationale: str = ""
    remediation: str = ""
    reproduction_steps: list[ReproductionStep] = Field(default_factory=list)
    evidence_items: list[EvidenceItem] = Field(default_factory=list)
    quality_warnings: list[ReportQualityWarning] = Field(default_factory=list)
    safety_notice: str = (
        "Authorized, local-only evidence organization; "
        "no requests are sent or replayed."
    )
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


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


class ExpectedResult(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    UNKNOWN = "unknown"


class ObservedResult(StrEnum):
    ALLOWED = "allowed"
    DENIED = "denied"
    ERROR = "error"
    UNKNOWN = "unknown"
    NOT_TESTED = "not_tested"


class BoundaryType(StrEnum):
    USER = "user"
    ORGANIZATION = "organization"
    TENANT = "tenant"
    ROLE = "role"
    SUBSCRIPTION = "subscription"
    OWNERSHIP = "ownership"
    UNKNOWN = "unknown"


class AuthzFindingType(StrEnum):
    IDOR = "idor"
    BOLA = "bola"
    BROKEN_ROLE_AUTHORIZATION = "broken_role_authorization"
    CROSS_TENANT_ACCESS = "cross_tenant_access"
    CROSS_ORG_ACCESS = "cross_org_access"
    STATE_CHANGING_AUTHZ_FAILURE = "state_changing_authz_failure"
    SENSITIVE_METADATA_EXPOSURE = "sensitive_metadata_exposure"
    NEEDS_MANUAL_REVIEW = "needs_manual_review"


class AuthzActor(BaseModel):
    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    role: str = Field(min_length=1)
    organization: str = ""
    tenant: str = ""
    account_type: str = ""
    notes: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class AuthzObject(BaseModel):
    id: str = Field(min_length=1)
    object_type: str = Field(min_length=1)
    display_name: str = Field(min_length=1)
    owner_actor_id: str = Field(min_length=1)
    organization: str = ""
    tenant: str = ""
    identifiers: dict[str, str] = Field(default_factory=dict)
    sensitivity: str = "unknown"
    notes: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class AuthzEndpointTemplate(BaseModel):
    id: str = Field(min_length=1)
    method: str = "UNKNOWN"
    path_template: str = Field(min_length=1)
    normalized_path: str = Field(min_length=1)
    risk_tags: list[str] = Field(default_factory=list)
    object_id_candidates: list[str] = Field(default_factory=list)
    source_endpoint_id: str = ""
    source_file: str = ""
    notes: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class ExpectedAccessRule(BaseModel):
    id: str = Field(min_length=1)
    actor_id: str = Field(min_length=1)
    object_id: str = Field(min_length=1)
    endpoint_template_id: str = Field(min_length=1)
    expected_result: ExpectedResult
    reason: str = ""
    boundary_type: BoundaryType = BoundaryType.UNKNOWN
    created_at: datetime = Field(default_factory=utc_now)


class ObservedAccessResult(BaseModel):
    id: str = Field(min_length=1)
    actor_id: str = Field(min_length=1)
    object_id: str = Field(min_length=1)
    endpoint_template_id: str = Field(min_length=1)
    observed_result: ObservedResult
    status_code: int | None = None
    response_length: int | None = None
    content_hash: str = ""
    key_fields_visible: list[str] = Field(default_factory=list)
    data_changed: bool | None = None
    error_message: str = ""
    evidence_reference: str = ""
    notes: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class AuthzFinding(BaseModel):
    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    finding_type: AuthzFindingType
    severity: Severity
    confidence: Confidence
    actor_id: str
    object_id: str
    endpoint_template_id: str
    expected_result: ExpectedResult
    observed_result: ObservedResult
    evidence_reference: str = ""
    impact: str = ""
    recommendation: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class AuthzMatrix(BaseModel):
    project_name: str = Field(min_length=1)
    actors: list[AuthzActor] = Field(default_factory=list)
    objects: list[AuthzObject] = Field(default_factory=list)
    endpoint_templates: list[AuthzEndpointTemplate] = Field(default_factory=list)
    expected_access: list[ExpectedAccessRule] = Field(default_factory=list)
    observed_results: list[ObservedAccessResult] = Field(default_factory=list)
    findings: list[AuthzFinding] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=utc_now)
    summary: dict[str, Any] = Field(default_factory=dict)
