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


class GraphQLOperationType(StrEnum):
    QUERY = "query"
    MUTATION = "mutation"
    SUBSCRIPTION = "subscription"
    UNKNOWN = "unknown"


class GraphQLSchemaArtifactType(StrEnum):
    INTROSPECTION_JSON = "introspection_json"
    SCHEMA_SDL = "schema_sdl"
    EMBEDDED_SCHEMA = "embedded_schema"
    TYPE_LISTING = "type_listing"
    UNKNOWN = "unknown"


class GraphQLReviewLeadCategory(StrEnum):
    AUTHORIZATION_REVIEW = "authorization_review"
    IDOR_BOLA_CANDIDATE = "idor_bola_candidate"
    SENSITIVE_FIELD_EXPOSURE = "sensitive_field_exposure"
    STATE_CHANGING_MUTATION = "state_changing_mutation"
    ADMIN_OPERATION = "admin_operation"
    BILLING_OPERATION = "billing_operation"
    FILE_OPERATION = "file_operation"
    TENANT_BOUNDARY = "tenant_boundary"
    ORG_BOUNDARY = "org_boundary"
    ROLE_BOUNDARY = "role_boundary"
    BATCHING_INDICATOR = "batching_indicator"
    INTROSPECTION_ARTIFACT = "introspection_artifact"
    EXCESSIVE_ERROR_DETAIL = "excessive_error_detail"
    NEEDS_MANUAL_REVIEW = "needs_manual_review"


class GraphQLEndpoint(BaseModel):
    id: str
    url: str = ""
    host: str = ""
    path: str = ""
    method: str = "UNKNOWN"
    source_type: str = ""
    source_file: str = ""
    source_module: str = "graphql-risk-mapper"
    occurrences: int = 1
    auth_indicators: list[str] = Field(default_factory=list)
    risk_tags: list[str] = Field(default_factory=list)
    evidence: str = ""
    redacted_evidence: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class GraphQLVariable(BaseModel):
    name: str
    value_type: str = ""
    observed_value_summary: str = ""
    sensitive: bool = False
    object_id_candidate: bool = False
    risk_tags: list[str] = Field(default_factory=list)


class GraphQLFragment(BaseModel):
    name: str
    fields: list[str] = Field(default_factory=list)
    source_file: str = ""
    evidence: str = ""
    redacted_evidence: str = ""


class GraphQLOperation(BaseModel):
    id: str
    operation_type: GraphQLOperationType = GraphQLOperationType.UNKNOWN
    operation_name: str = ""
    endpoint_id: str = ""
    source_type: str = ""
    source_file: str = ""
    source_module: str = "graphql-risk-mapper"
    variables: list[str] = Field(default_factory=list)
    variable_types: dict[str, str] = Field(default_factory=dict)
    fields: list[str] = Field(default_factory=list)
    fragments: list[str] = Field(default_factory=list)
    sensitive_fields: list[str] = Field(default_factory=list)
    object_id_candidates: list[str] = Field(default_factory=list)
    risk_tags: list[str] = Field(default_factory=list)
    evidence: str = ""
    redacted_evidence: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class GraphQLSchemaArtifact(BaseModel):
    id: str
    source_type: str = ""
    source_file: str = ""
    artifact_type: GraphQLSchemaArtifactType = GraphQLSchemaArtifactType.UNKNOWN
    type_names: list[str] = Field(default_factory=list)
    query_names: list[str] = Field(default_factory=list)
    mutation_names: list[str] = Field(default_factory=list)
    subscription_names: list[str] = Field(default_factory=list)
    sensitive_types: list[str] = Field(default_factory=list)
    sensitive_fields: list[str] = Field(default_factory=list)
    evidence: str = ""
    redacted_evidence: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class GraphQLReviewLead(BaseModel):
    id: str
    category: GraphQLReviewLeadCategory
    title: str
    endpoint_id: str = ""
    operation_id: str = ""
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.MEDIUM
    reason: str = ""
    manual_questions: list[str] = Field(default_factory=list)
    evidence: str = ""
    redacted_evidence: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class GraphQLInventory(BaseModel):
    project_name: str = "BugBountyScout GraphQL risk inventory"
    endpoints: list[GraphQLEndpoint] = Field(default_factory=list)
    operations: list[GraphQLOperation] = Field(default_factory=list)
    variables: list[GraphQLVariable] = Field(default_factory=list)
    fragments: list[GraphQLFragment] = Field(default_factory=list)
    schema_artifacts: list[GraphQLSchemaArtifact] = Field(default_factory=list)
    review_leads: list[GraphQLReviewLead] = Field(default_factory=list)
    source_files: list[str] = Field(default_factory=list)
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


class VocabularyCategory(StrEnum):
    QUERY_PARAM = "query_param"
    BODY_PARAM = "body_param"
    JSON_KEY = "json_key"
    RESPONSE_KEY = "response_key"
    FORM_FIELD = "form_field"
    HEADER_NAME = "header_name"
    COOKIE_NAME = "cookie_name"
    ROUTE_SEGMENT = "route_segment"
    ENDPOINT_PATH = "endpoint_path"
    OBJECT_NAME = "object_name"
    GRAPHQL_VARIABLE = "graphql_variable"
    GRAPHQL_OPERATION = "graphql_operation"
    JAVASCRIPT_IDENTIFIER = "javascript_identifier"
    ERROR_FIELD = "error_field"
    AUTH_TERM = "auth_term"
    ADMIN_TERM = "admin_term"
    BILLING_TERM = "billing_term"
    FILE_TERM = "file_term"
    ORGANIZATION_TERM = "organization_term"
    ROLE_PERMISSION_TERM = "role_permission_term"
    DEBUG_TERM = "debug_term"
    UNKNOWN = "unknown"


class VocabularyTerm(BaseModel):
    id: str = Field(min_length=1)
    value: str = Field(min_length=1)
    normalized_value: str = Field(min_length=1)
    category: VocabularyCategory = VocabularyCategory.UNKNOWN
    source_type: str = ""
    source_file: str = ""
    source_module: str = "paramforge"
    context: str = ""
    occurrences: int = Field(default=1, ge=1)
    risk_score: int = Field(default=0, ge=0, le=100)
    frequency_score: int = Field(default=1, ge=0, le=100)
    tags: list[str] = Field(default_factory=list)
    evidence: str = ""
    redacted_evidence: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class VocabularyInventory(BaseModel):
    project_name: str = "BugBountyScout ParamForge inventory"
    terms: list[VocabularyTerm] = Field(default_factory=list)
    categories: dict[str, int] = Field(default_factory=dict)
    source_files: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=utc_now)
    summary: dict[str, Any] = Field(default_factory=dict)


class JwtObservation(BaseModel):
    id: str
    token_fingerprint: str
    source_type: str = ""
    source_file: str = ""
    source_module: str = "auth-surface-analyzer"
    location: str = ""
    algorithm: str = ""
    token_type: str = ""
    key_id: str = ""
    issuer: str = ""
    subject_present: bool = False
    audience: list[str] = Field(default_factory=list)
    issued_at: datetime | None = None
    not_before: datetime | None = None
    expires_at: datetime | None = None
    lifetime_seconds: int | None = None
    scopes: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    tenant_claims: list[str] = Field(default_factory=list)
    org_claims: list[str] = Field(default_factory=list)
    sensitive_claims: list[str] = Field(default_factory=list)
    custom_claim_keys: list[str] = Field(default_factory=list)
    risk_tags: list[str] = Field(default_factory=list)
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.HIGH
    evidence: str = ""
    redacted_evidence: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class CookieObservation(BaseModel):
    id: str
    name: str
    source_type: str = ""
    source_file: str = ""
    source_module: str = "auth-surface-analyzer"
    location: str = ""
    cookie_type: str = "unknown"
    domain: str = ""
    path: str = ""
    secure: bool | None = None
    httponly: bool | None = None
    samesite: str = ""
    expires: str = ""
    max_age: int | None = None
    prefix: str = ""
    risk_tags: list[str] = Field(default_factory=list)
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.HIGH
    evidence: str = ""
    redacted_evidence: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class SecurityHeaderObservation(BaseModel):
    id: str
    header_name: str
    value_summary: str = ""
    source_type: str = ""
    source_file: str = ""
    source_module: str = "auth-surface-analyzer"
    url: str = ""
    status_code: int | None = None
    risk_tags: list[str] = Field(default_factory=list)
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.HIGH
    evidence: str = ""
    redacted_evidence: str = ""
    recommendation: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class CorsObservation(BaseModel):
    id: str
    source_type: str = ""
    source_file: str = ""
    source_module: str = "auth-surface-analyzer"
    url: str = ""
    allow_origin: str = ""
    allow_credentials: bool = False
    allow_methods: list[str] = Field(default_factory=list)
    allow_headers: list[str] = Field(default_factory=list)
    expose_headers: list[str] = Field(default_factory=list)
    vary: str = ""
    risk_tags: list[str] = Field(default_factory=list)
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.HIGH
    evidence: str = ""
    redacted_evidence: str = ""
    recommendation: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class CacheObservation(BaseModel):
    id: str
    source_type: str = ""
    source_file: str = ""
    source_module: str = "auth-surface-analyzer"
    url: str = ""
    status_code: int | None = None
    cache_control: str = ""
    pragma: str = ""
    expires: str = ""
    content_type: str = ""
    sensitive_context: bool = False
    risk_tags: list[str] = Field(default_factory=list)
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.MEDIUM
    evidence: str = ""
    redacted_evidence: str = ""
    recommendation: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class AuthSurfaceInventory(BaseModel):
    project_name: str = "BugBountyScout Auth Surface inventory"
    jwt_observations: list[JwtObservation] = Field(default_factory=list)
    cookie_observations: list[CookieObservation] = Field(default_factory=list)
    security_header_observations: list[SecurityHeaderObservation] = Field(
        default_factory=list
    )
    cors_observations: list[CorsObservation] = Field(default_factory=list)
    cache_observations: list[CacheObservation] = Field(default_factory=list)
    auth_endpoints: list[Endpoint] = Field(default_factory=list)
    session_review_leads: list[str] = Field(default_factory=list)
    source_files: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=utc_now)
    summary: dict[str, Any] = Field(default_factory=dict)


class WordlistExport(BaseModel):
    name: str
    category: str
    terms: list[str] = Field(default_factory=list)
    output_format: str
    generated_at: datetime = Field(default_factory=utc_now)
    source_inventory: str = ""


class ArtifactType(StrEnum):
    HAR_REPORT = "har_report"
    ENDPOINT_INVENTORY = "endpoint_inventory"
    FRONTEND_INVENTORY = "frontend_inventory"
    PARAMFORGE_INVENTORY = "paramforge_inventory"
    AUTH_SURFACE_INVENTORY = "auth_surface_inventory"
    GRAPHQL_INVENTORY = "graphql_inventory"
    AUTHZ_MATRIX = "authz_matrix"
    EVIDENCE_WORKSPACE = "evidence_workspace"
    FINDING = "finding"
    MARKDOWN_REPORT = "markdown_report"
    JSON_REPORT = "json_report"
    UNKNOWN = "unknown"


class LeadCategory(StrEnum):
    IDOR_BOLA = "idor_bola"
    BROKEN_ROLE_AUTHORIZATION = "broken_role_authorization"
    CROSS_TENANT_REVIEW = "cross_tenant_review"
    CROSS_ORG_REVIEW = "cross_org_review"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    EXPOSED_SECRET_REVIEW = "exposed_secret_review"
    FRONTEND_CONFIG_EXPOSURE = "frontend_config_exposure"
    SOURCE_MAP_REVIEW = "source_map_review"
    JWT_REVIEW = "jwt_review"
    SESSION_COOKIE_REVIEW = "session_cookie_review"
    CORS_REVIEW = "cors_review"
    CACHE_REVIEW = "cache_review"
    GRAPHQL_AUTHORIZATION_REVIEW = "graphql_authorization_review"
    GRAPHQL_SENSITIVE_FIELD_REVIEW = "graphql_sensitive_field_review"
    FILE_UPLOAD_REVIEW = "file_upload_review"
    FILE_DOWNLOAD_REVIEW = "file_download_review"
    BILLING_REVIEW = "billing_review"
    ADMIN_REVIEW = "admin_review"
    AUTH_FLOW_REVIEW = "auth_flow_review"
    DEBUG_LEAK_REVIEW = "debug_leak_review"
    REPORT_READY_CANDIDATE = "report_ready_candidate"
    NEEDS_MORE_EVIDENCE = "needs_more_evidence"
    LIKELY_NOISE = "likely_noise"
    NEEDS_MANUAL_REVIEW = "needs_manual_review"


class Priority(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Reportability(StrEnum):
    REPORT_READY = "report_ready"
    NEEDS_MORE_EVIDENCE = "needs_more_evidence"
    NEEDS_MANUAL_VALIDATION = "needs_manual_validation"
    LIKELY_DUPLICATE = "likely_duplicate"
    LIKELY_INFORMATIONAL = "likely_informational"
    LIKELY_NOISE = "likely_noise"


class ProjectArtifact(BaseModel):
    id: str
    artifact_type: ArtifactType = ArtifactType.UNKNOWN
    path: str
    source_module: str = ""
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    parsed: bool = False
    parse_error: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class CorrelatedAsset(BaseModel):
    id: str
    asset_type: str = "endpoint"
    host: str = ""
    path: str = ""
    method: str = "UNKNOWN"
    normalized_path: str = ""
    source_modules: list[str] = Field(default_factory=list)
    related_artifacts: list[str] = Field(default_factory=list)
    related_endpoints: list[str] = Field(default_factory=list)
    related_graphql_operations: list[str] = Field(default_factory=list)
    related_auth_observations: list[str] = Field(default_factory=list)
    related_frontend_findings: list[str] = Field(default_factory=list)
    related_authz_findings: list[str] = Field(default_factory=list)
    related_evidence_workspaces: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    risk_score: int = Field(default=0, ge=0, le=100)
    confidence: Confidence = Confidence.MEDIUM
    created_at: datetime = Field(default_factory=utc_now)


class RiskSignal(BaseModel):
    id: str
    signal_type: str
    title: str
    source_module: str
    source_artifact_id: str
    asset_id: str = ""
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.MEDIUM
    tags: list[str] = Field(default_factory=list)
    evidence: str = ""
    redacted_evidence: str = ""
    reason: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class TriageLead(BaseModel):
    id: str
    title: str
    category: LeadCategory
    affected_asset_id: str = ""
    source_signals: list[str] = Field(default_factory=list)
    priority: Priority = Priority.INFORMATIONAL
    confidence: Confidence = Confidence.MEDIUM
    severity_estimate: Severity = Severity.INFO
    reason: str = ""
    manual_validation_steps: list[str] = Field(default_factory=list)
    suggested_evidence_to_collect: list[str] = Field(default_factory=list)
    reportability: Reportability = Reportability.NEEDS_MANUAL_VALIDATION
    related_evidence: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)


class ProjectCorrelationInventory(BaseModel):
    project_name: str = "BugBountyScout correlation project"
    artifacts: list[ProjectArtifact] = Field(default_factory=list)
    assets: list[CorrelatedAsset] = Field(default_factory=list)
    signals: list[RiskSignal] = Field(default_factory=list)
    triage_leads: list[TriageLead] = Field(default_factory=list)
    source_files: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=utc_now)
    summary: dict[str, Any] = Field(default_factory=dict)


class WorkflowInputType(StrEnum):
    HAR = "har"
    JAVASCRIPT = "javascript"
    HTML = "html"
    JSON = "json"
    YAML = "yaml"
    TEXT = "text"
    SOURCE_MAP = "source_map"
    GRAPHQL = "graphql"
    RAW_REQUEST = "raw_request"
    RAW_RESPONSE = "raw_response"
    ENDPOINT_INVENTORY = "endpoint_inventory"
    FRONTEND_INVENTORY = "frontend_inventory"
    AUTH_SURFACE_INVENTORY = "auth_surface_inventory"
    GRAPHQL_INVENTORY = "graphql_inventory"
    PARAMFORGE_INVENTORY = "paramforge_inventory"
    AUTHZ_MATRIX = "authz_matrix"
    EVIDENCE_WORKSPACE = "evidence_workspace"
    CORRELATION_PROJECT = "correlation_project"
    UNKNOWN = "unknown"


class WorkflowStepStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


class WorkflowOutputType(StrEnum):
    HAR_REPORT = "har_report"
    ENDPOINT_INVENTORY = "endpoint_inventory"
    FRONTEND_INVENTORY = "frontend_inventory"
    AUTH_SURFACE_INVENTORY = "auth_surface_inventory"
    GRAPHQL_INVENTORY = "graphql_inventory"
    PARAMFORGE_INVENTORY = "paramforge_inventory"
    AUTHZ_MATRIX = "authz_matrix"
    EVIDENCE_WORKSPACE = "evidence_workspace"
    CORRELATION_PROJECT = "correlation_project"
    CORRELATION_REPORT = "correlation_report"
    TRIAGE_LEADS = "triage_leads"
    CHECKLIST = "checklist"
    MARKDOWN_REPORT = "markdown_report"
    JSON_REPORT = "json_report"
    LOG = "log"
    UNKNOWN = "unknown"


class WorkflowInput(BaseModel):
    id: str
    path: str
    input_type: WorkflowInputType = WorkflowInputType.UNKNOWN
    size_bytes: int = Field(default=0, ge=0)
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    detected_modules: list[str] = Field(default_factory=list)
    parse_status: str = "detected"
    notes: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)


class WorkflowStep(BaseModel):
    id: str
    name: str
    module: str
    status: WorkflowStepStatus = WorkflowStepStatus.PENDING
    input_ids: list[str] = Field(default_factory=list)
    output_paths: list[str] = Field(default_factory=list)
    skipped_reason: str = ""
    warning_messages: list[str] = Field(default_factory=list)
    error_message: str = ""
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_seconds: float | None = Field(default=None, ge=0)


class WorkflowOutput(BaseModel):
    id: str
    path: str
    output_type: WorkflowOutputType = WorkflowOutputType.UNKNOWN
    source_step_id: str
    source_module: str
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    size_bytes: int = Field(default=0, ge=0)
    redacted: bool = True
    created_at: datetime = Field(default_factory=utc_now)


class WorkflowSummary(BaseModel):
    total_inputs: int = 0
    total_steps: int = 0
    completed_steps: int = 0
    skipped_steps: int = 0
    failed_steps: int = 0
    total_outputs: int = 0
    high_priority_leads: list[dict[str, Any]] = Field(default_factory=list)
    report_ready_candidates: list[dict[str, Any]] = Field(default_factory=list)
    needs_more_evidence_count: int = 0
    warnings: list[str] = Field(default_factory=list)
    next_manual_actions: list[str] = Field(default_factory=list)


class WorkflowManifest(BaseModel):
    id: str
    project_name: str
    workspace_path: str
    input_dir: str = "inputs"
    output_dir: str = "outputs"
    report_dir: str = "reports"
    evidence_dir: str = "evidence"
    scope_file: str = "scope.yml"
    inputs: list[WorkflowInput] = Field(default_factory=list)
    steps: list[WorkflowStep] = Field(default_factory=list)
    outputs: list[WorkflowOutput] = Field(default_factory=list)
    correlation_project: str = ""
    summary: WorkflowSummary = Field(default_factory=WorkflowSummary)
    safety_notice: str = (
        "Authorized local-file analysis only. No live requests, request replay, "
        "fuzzing, payload generation, exploit automation, cloud calls, or telemetry."
    )
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class PlatformProfile(StrEnum):
    GENERIC = "generic"
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"
    YESWEHACK = "yeswehack"
    GITHUB_SECURITY_ADVISORY = "github_security_advisory"
    INTERNAL = "internal"


class SubmissionStatus(StrEnum):
    DRAFT = "draft"
    NEEDS_REVIEW = "needs_review"
    READY = "ready"
    BLOCKED = "blocked"


class AttachmentType(StrEnum):
    MARKDOWN_REPORT = "markdown_report"
    JSON_REPORT = "json_report"
    SCREENSHOT = "screenshot"
    REQUEST_RESPONSE = "request_response"
    HAR_EXCERPT = "har_excerpt"
    ENDPOINT_INVENTORY = "endpoint_inventory"
    FRONTEND_INVENTORY = "frontend_inventory"
    AUTH_SURFACE_INVENTORY = "auth_surface_inventory"
    GRAPHQL_INVENTORY = "graphql_inventory"
    AUTHZ_MATRIX = "authz_matrix"
    EVIDENCE_WORKSPACE = "evidence_workspace"
    CORRELATION_REPORT = "correlation_report"
    WORKFLOW_REPORT = "workflow_report"
    NOTE = "note"
    OTHER = "other"


class ChecklistStatus(StrEnum):
    PASS = "pass"
    WARNING = "warning"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"


class SubmissionAttachment(BaseModel):
    id: str
    title: str
    path: str = ""
    attachment_type: AttachmentType = AttachmentType.OTHER
    sha256: str = Field(default="", pattern=r"^$|^[a-fA-F0-9]{64}$")
    size_bytes: int = Field(default=0, ge=0)
    redacted: bool = True
    include_in_package: bool = True
    notes: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class SubmissionChecklistItem(BaseModel):
    id: str
    category: str
    text: str
    status: ChecklistStatus = ChecklistStatus.WARNING
    blocking: bool = False
    recommendation: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class SubmissionDraft(BaseModel):
    id: str
    title: str
    vulnerability_class: str = ""
    severity_estimate: Severity = Severity.INFO
    confidence: Confidence = Confidence.MEDIUM
    affected_assets: list[str] = Field(default_factory=list)
    summary: str = ""
    impact: str = ""
    steps_to_reproduce: list[str] = Field(default_factory=list)
    expected_behavior: str = ""
    actual_behavior: str = ""
    evidence_summary: str = ""
    remediation: str = ""
    limitations: str = ""
    reporter_notes: str = ""
    scope_notes: str = ""
    severity_rationale: str = ""
    platform_profile: PlatformProfile = PlatformProfile.GENERIC
    source_type: str = ""
    source_file: str = ""
    attachments: list[SubmissionAttachment] = Field(default_factory=list)
    quality_warnings: list[str] = Field(default_factory=list)
    redaction_warnings: list[str] = Field(default_factory=list)
    status: SubmissionStatus = SubmissionStatus.DRAFT
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class SubmissionPackage(BaseModel):
    id: str
    title: str
    platform_profile: PlatformProfile = PlatformProfile.GENERIC
    source_type: str = ""
    source_file: str = ""
    output_dir: str = ""
    report_markdown: str = ""
    report_json: str = ""
    attachments: list[SubmissionAttachment] = Field(default_factory=list)
    attachment_manifest: str = ""
    quality_warnings: list[str] = Field(default_factory=list)
    redaction_warnings: list[str] = Field(default_factory=list)
    final_checklist: list[SubmissionChecklistItem] = Field(default_factory=list)
    status: SubmissionStatus = SubmissionStatus.DRAFT
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
