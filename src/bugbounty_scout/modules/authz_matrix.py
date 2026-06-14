"""Local, manual-first IDOR/BOLA authorization testing workbench."""

import json
import re
from hashlib import sha256
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from bugbounty_scout.models import (
    ApiInventory,
    AuthzActor,
    AuthzEndpointTemplate,
    AuthzFinding,
    AuthzMatrix,
    AuthzObject,
    ExpectedAccessRule,
    ObservedAccessResult,
)
from bugbounty_scout.modules.endpoints import normalize_path
from bugbounty_scout.redaction import redact_text

SAFETY_NOTICE = (
    "Authorized, owned-asset, or lab use only. This matrix stores manual notes and "
    "does not send, replay, fuzz, or generate HTTP requests."
)
HIGH_INTEREST_TAGS = {
    "idor-candidate",
    "state-changing",
    "admin",
    "billing",
    "user-profile",
    "file-upload",
    "file-download",
    "export",
    "invite",
    "organization-management",
    "permission-management",
    "role-management",
    "sensitive-data",
}


def _id(prefix: str, *parts: object) -> str:
    value = "|".join(str(part) for part in parts)
    return f"{prefix}-{sha256(value.encode()).hexdigest()[:12]}"


def new_matrix(project_name: str) -> AuthzMatrix:
    """Create an empty authorization matrix."""
    name = project_name.strip()
    if not name:
        raise ValueError("Project name must not be blank")
    return AuthzMatrix(
        project_name=name,
        summary={"safety_notice": SAFETY_NOTICE, "workflow": "manual-first"},
    )


def load_matrix(path: Path) -> AuthzMatrix:
    """Load and validate a YAML or JSON matrix."""
    try:
        raw = path.read_text(encoding="utf-8")
        data = (
            json.loads(raw) if path.suffix.lower() == ".json" else yaml.safe_load(raw)
        )
        if not isinstance(data, dict):
            raise ValueError("matrix root must be an object")
        return AuthzMatrix.model_validate(data)
    except OSError as exc:
        raise ValueError(f"Could not read matrix {path}: {exc}") from exc
    except (json.JSONDecodeError, yaml.YAMLError, ValidationError, ValueError) as exc:
        raise ValueError(f"Invalid authorization matrix {path}: {exc}") from exc


def save_matrix(matrix: AuthzMatrix, path: Path) -> Path:
    """Write a matrix, redacting string values by default."""
    data = matrix.model_dump(mode="json")
    safe = _redact(data)
    try:
        if path.suffix.lower() == ".json":
            content = json.dumps(safe, indent=2)
        else:
            content = yaml.safe_dump(safe, sort_keys=False)
        path.write_text(
            content + ("" if content.endswith("\n") else "\n"), encoding="utf-8"
        )
    except OSError as exc:
        raise ValueError(f"Could not write matrix {path}: {exc}") from exc
    return path


def _redact(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            name = str(key)
            if isinstance(item, str) and re.search(
                r"(?i)(api.?key|token|secret|password|session|cookie|authorization)",
                name,
            ):
                result[name] = "<redacted-secret>"
            else:
                result[name] = _redact(item)
        return result
    return value


def add_actor(matrix: AuthzMatrix, name: str, role: str, **kwargs: str) -> AuthzActor:
    actor = AuthzActor(
        id=_id("actor", name, role, len(matrix.actors)), name=name, role=role, **kwargs
    )
    matrix.actors.append(actor)
    return actor


def add_object(
    matrix: AuthzMatrix,
    object_type: str,
    name: str,
    owner_actor_id: str,
    identifiers: dict[str, str] | None = None,
    **kwargs: str,
) -> AuthzObject:
    _require(matrix, owner_actor_id, "actor")
    safe_identifiers = _redact(identifiers or {})
    item = AuthzObject(
        id=_id("object", object_type, name, owner_actor_id, len(matrix.objects)),
        object_type=object_type,
        display_name=name,
        owner_actor_id=owner_actor_id,
        identifiers=safe_identifiers,
        **kwargs,
    )
    matrix.objects.append(item)
    return item


def add_endpoint(
    matrix: AuthzMatrix,
    method: str,
    path: str,
    risk_tags: list[str] | None = None,
    **kwargs: Any,
) -> AuthzEndpointTemplate:
    normalized = normalize_path(path)
    candidates = kwargs.pop("object_id_candidates", None) or [
        part[1:-1]
        for part in path.split("/")
        if part.startswith("{") and part.endswith("}")
    ]
    endpoint = AuthzEndpointTemplate(
        id=_id("authz-ep", method.upper(), normalized),
        method=method.upper(),
        path_template=path,
        normalized_path=normalized,
        risk_tags=sorted(set(risk_tags or [])),
        object_id_candidates=sorted(set(candidates)),
        **kwargs,
    )
    if not any(item.id == endpoint.id for item in matrix.endpoint_templates):
        matrix.endpoint_templates.append(endpoint)
    return endpoint


def import_endpoints(matrix: AuthzMatrix, path: Path) -> list[AuthzEndpointTemplate]:
    try:
        inventory = ApiInventory.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError, ValueError) as exc:
        raise ValueError(f"Invalid endpoint inventory {path}: {exc}") from exc
    imported = []
    for endpoint in inventory.endpoints:
        if not HIGH_INTEREST_TAGS.intersection(endpoint.risk_tags):
            continue
        imported.append(
            add_endpoint(
                matrix,
                endpoint.method,
                endpoint.normalized_path or endpoint.path,
                endpoint.risk_tags,
                object_id_candidates=endpoint.object_id_candidates,
                source_endpoint_id=endpoint.id,
                source_file=endpoint.source_file,
            )
        )
    return imported


def add_expectation(
    matrix: AuthzMatrix,
    actor_id: str,
    object_id: str,
    endpoint_id: str,
    result: str,
    reason: str,
    boundary_type: str = "unknown",
) -> ExpectedAccessRule:
    _validate_refs(matrix, actor_id, object_id, endpoint_id)
    rule = ExpectedAccessRule(
        id=_id("expect", actor_id, object_id, endpoint_id),
        actor_id=actor_id,
        object_id=object_id,
        endpoint_template_id=endpoint_id,
        expected_result=result,
        reason=reason,
        boundary_type=boundary_type,
    )
    matrix.expected_access = [
        item for item in matrix.expected_access if item.id != rule.id
    ]
    matrix.expected_access.append(rule)
    return rule


def record_result(
    matrix: AuthzMatrix,
    actor_id: str,
    object_id: str,
    endpoint_id: str,
    result: str,
    **kwargs: Any,
) -> ObservedAccessResult:
    _validate_refs(matrix, actor_id, object_id, endpoint_id)
    observed = ObservedAccessResult(
        id=_id("observed", actor_id, object_id, endpoint_id),
        actor_id=actor_id,
        object_id=object_id,
        endpoint_template_id=endpoint_id,
        observed_result=result,
        **kwargs,
    )
    matrix.observed_results = [
        item for item in matrix.observed_results if item.id != observed.id
    ]
    matrix.observed_results.append(observed)
    return observed


def _require(matrix: AuthzMatrix, value: str, kind: str) -> None:
    collection = {
        "actor": matrix.actors,
        "object": matrix.objects,
        "endpoint": matrix.endpoint_templates,
    }[kind]
    if not any(item.id == value for item in collection):
        raise ValueError(f"Unknown {kind} ID: {value}")


def _validate_refs(matrix: AuthzMatrix, actor: str, obj: str, endpoint: str) -> None:
    _require(matrix, actor, "actor")
    _require(matrix, obj, "object")
    _require(matrix, endpoint, "endpoint")


def compare(matrix: AuthzMatrix) -> list[dict[str, Any]]:
    """Compare explicitly modeled expectations with manual observations."""
    observed = {
        (item.actor_id, item.object_id, item.endpoint_template_id): item
        for item in matrix.observed_results
    }
    rows = []
    for rule in matrix.expected_access:
        result = observed.get(
            (rule.actor_id, rule.object_id, rule.endpoint_template_id)
        )
        mismatch = bool(
            result
            and result.observed_result not in {"not_tested", "unknown"}
            and (
                (rule.expected_result == "deny" and result.observed_result == "allowed")
                or (
                    rule.expected_result == "allow"
                    and result.observed_result != "allowed"
                )
                or (
                    rule.expected_result == "unknown"
                    and result.observed_result == "allowed"
                )
            )
        )
        rows.append(
            {
                "expected_rule_id": rule.id,
                "actor_id": rule.actor_id,
                "object_id": rule.object_id,
                "endpoint_template_id": rule.endpoint_template_id,
                "boundary_type": rule.boundary_type.value,
                "expected_result": rule.expected_result.value,
                "observed_result": result.observed_result.value
                if result
                else "not_tested",
                "mismatch": mismatch,
                "evidence_reference": result.evidence_reference if result else "",
            }
        )
    return rows


def generate_findings(matrix: AuthzMatrix) -> list[AuthzFinding]:
    """Generate conservative candidate findings from mismatches."""
    rules = {item.id: item for item in matrix.expected_access}
    objects = {item.id: item for item in matrix.objects}
    endpoints = {item.id: item for item in matrix.endpoint_templates}
    results = {
        (item.actor_id, item.object_id, item.endpoint_template_id): item
        for item in matrix.observed_results
    }
    findings = []
    for row in compare(matrix):
        if not row["mismatch"]:
            continue
        rule = rules[row["expected_rule_id"]]
        result = results.get((rule.actor_id, rule.object_id, rule.endpoint_template_id))
        obj, endpoint = objects[rule.object_id], endpoints[rule.endpoint_template_id]
        unauthorized = (
            rule.expected_result == "deny" and row["observed_result"] == "allowed"
        )
        state_change = "state-changing" in endpoint.risk_tags or endpoint.method in {
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        }
        if not unauthorized:
            finding_type, severity = "needs_manual_review", "info"
        elif state_change:
            finding_type, severity = "state_changing_authz_failure", "high"
        elif rule.boundary_type == "tenant":
            finding_type, severity = "cross_tenant_access", "high"
        elif rule.boundary_type == "organization":
            finding_type, severity = "cross_org_access", "high"
        elif rule.boundary_type == "role":
            finding_type, severity = "broken_role_authorization", "medium"
        else:
            finding_type = "idor" if endpoint.method == "GET" else "bola"
            severity = "high" if obj.sensitivity == "high" else "medium"
        evidence = result.evidence_reference if result else ""
        findings.append(
            AuthzFinding(
                id=_id("authz-finding", rule.id, row["observed_result"]),
                title=f"Authorization mismatch for {obj.display_name}",
                finding_type=finding_type,
                severity=severity,
                confidence="high" if evidence else "medium",
                actor_id=rule.actor_id,
                object_id=rule.object_id,
                endpoint_template_id=rule.endpoint_template_id,
                expected_result=rule.expected_result,
                observed_result=row["observed_result"],
                evidence_reference=evidence,
                impact=(
                    "Manual observations differ from the documented authorization "
                    "expectation; validate scope, ownership, and returned or changed data."
                ),
                recommendation=(
                    "Enforce server-side authorization for role, tenant, organization, "
                    "and object ownership before returning data or applying changes."
                ),
            )
        )
    matrix.findings = findings
    return findings


def generate_checklist(matrix: AuthzMatrix) -> list[dict[str, str]]:
    questions: list[dict[str, str]] = []
    boundaries = {rule.boundary_type.value for rule in matrix.expected_access}
    templates = {
        "user": [
            "Can Actor A access an object owned by Actor B?",
            "Does the server enforce ownership rather than only hiding the object in the UI?",
            "Does a denied response still expose object metadata?",
        ],
        "organization": [
            "Can a user from Org A access Org B objects?",
            "Are organization identifiers enforced server-side?",
            "Are exports scoped to the correct organization?",
        ],
        "tenant": [
            "Can one tenant enumerate or access another tenant's resources?",
            "Are tenant identifiers enforced server-side?",
            "Can shared admin or support workflows cross tenant boundaries incorrectly?",
        ],
        "role": [
            "Can a lower-privileged role directly reach a higher-privileged operation?",
            "Are role checks enforced server-side on every request?",
        ],
    }
    for boundary in sorted(boundaries):
        for question in templates.get(boundary, []):
            questions.append({"category": boundary, "question": question})
    for endpoint in matrix.endpoint_templates:
        if "state-changing" in endpoint.risk_tags or endpoint.method in {
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        }:
            questions.extend(
                {
                    "category": "state-changing",
                    "endpoint_id": endpoint.id,
                    "question": text,
                }
                for text in [
                    "Can a lower-privileged user change an object they do not own?",
                    "Is role authorization enforced before the state change?",
                    "Is object ownership checked before mutation?",
                ]
            )
        if "admin" in endpoint.risk_tags:
            questions.extend(
                {"category": "admin", "endpoint_id": endpoint.id, "question": text}
                for text in [
                    "Is this endpoint protected server-side rather than only hidden in the UI?",
                    "Can non-admin roles reach the endpoint directly?",
                    "Are admin role checks applied on every request?",
                ]
            )
    return questions


def render_json(matrix: AuthzMatrix) -> str:
    generate_findings(matrix)
    data = matrix.model_dump(mode="json")
    data["mismatches"] = compare(matrix)
    data["manual_follow_up_checklist"] = generate_checklist(matrix)
    return json.dumps(_redact(data), indent=2)


def render_checklist_json(matrix: AuthzMatrix) -> str:
    return json.dumps(_redact(generate_checklist(matrix)), indent=2)


def render_checklist_markdown(matrix: AuthzMatrix) -> str:
    lines = ["# IDOR/BOLA Manual Checklist", "", SAFETY_NOTICE, ""]
    for item in generate_checklist(matrix):
        suffix = f" ({item['endpoint_id']})" if item.get("endpoint_id") else ""
        lines.append(f"- [ ] **{item['category']}**{suffix}: {item['question']}")
    if len(lines) == 4:
        lines.append(
            "_Add expected rules and endpoints to generate tailored questions._"
        )
    return redact_text("\n".join(lines))


def render_markdown(matrix: AuthzMatrix) -> str:
    findings = generate_findings(matrix)
    mismatches = [item for item in compare(matrix) if item["mismatch"]]
    lines = [
        f"# IDOR/BOLA Matrix — {matrix.project_name}",
        "",
        "## Summary",
        f"- Actors: {len(matrix.actors)}",
        f"- Objects: {len(matrix.objects)}",
        f"- Endpoint templates: {len(matrix.endpoint_templates)}",
        f"- Mismatches: {len(mismatches)}",
        f"- Candidate findings: {len(findings)}",
        "",
        "## Actors",
    ]
    lines += [
        f"- `{a.id}` — {a.name} ({a.role}); org={a.organization or '—'}; tenant={a.tenant or '—'}"
        for a in matrix.actors
    ] or ["_None._"]
    lines += ["", "## Objects"]
    lines += [
        f"- `{o.id}` — {o.display_name} ({o.object_type}); owner `{o.owner_actor_id}`; sensitivity={o.sensitivity}"
        for o in matrix.objects
    ] or ["_None._"]
    lines += ["", "## Endpoint templates"]
    lines += [
        f"- `{e.id}` — `{e.method} {e.path_template}`; tags: {', '.join(e.risk_tags) or 'none'}"
        for e in matrix.endpoint_templates
    ] or ["_None._"]
    lines += ["", "## Expected access matrix"]
    lines += [
        f"- `{r.actor_id}` → `{r.object_id}` via `{r.endpoint_template_id}`: **{r.expected_result.value}** ({r.boundary_type.value}) — {r.reason}"
        for r in matrix.expected_access
    ] or ["_None._"]
    lines += ["", "## Observed access matrix"]
    lines += [
        f"- `{r.actor_id}` → `{r.object_id}` via `{r.endpoint_template_id}`: **{r.observed_result.value}**; status={r.status_code or '—'}"
        for r in matrix.observed_results
    ] or ["_None._"]
    lines += ["", "## Mismatches"]
    lines += [
        f"- Expected **{r['expected_result']}**, observed **{r['observed_result']}** for `{r['expected_rule_id']}`."
        for r in mismatches
    ] or ["_None._"]
    lines += ["", "## Candidate findings"]
    lines += [
        f"- **{f.severity.value.upper()} — {f.title}** (`{f.finding_type.value}`): {f.impact}"
        for f in findings
    ] or ["_None._"]
    lines += ["", "## Evidence references"]
    evidence = sorted(
        {r.evidence_reference for r in matrix.observed_results if r.evidence_reference}
    )
    lines += [f"- {item}" for item in evidence] or ["_None recorded._"]
    lines += [
        "",
        "## Manual follow-up checklist",
        render_checklist_markdown(matrix),
        "",
        "## Redaction notice",
        "Sensitive-looking values are redacted by default. Store only intentionally redacted local evidence references.",
        "",
        "## Limitations",
        "This is a manual testing workbench. It does not send requests, replay traffic, generate payloads, fuzz, scan, or prove exploitability.",
    ]
    return redact_text("\n".join(lines))
