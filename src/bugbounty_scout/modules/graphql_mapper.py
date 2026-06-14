"""Passive, local-only GraphQL endpoint and authorization-risk mapping."""

import json
import re
from contextlib import suppress
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml
from pydantic import ValidationError

from bugbounty_scout.models import (
    Confidence,
    GraphQLEndpoint,
    GraphQLFragment,
    GraphQLInventory,
    GraphQLOperation,
    GraphQLReviewLead,
    GraphQLSchemaArtifact,
    GraphQLVariable,
)
from bugbounty_scout.redaction import redact_text

SUPPORTED = {
    ".har",
    ".js",
    ".html",
    ".htm",
    ".json",
    ".txt",
    ".graphql",
    ".gql",
    ".graphqls",
    ".yml",
    ".yaml",
}
ENDPOINT_RE = re.compile(
    r"(?:(?:https?|wss?)://[^\s\"'<>]+)?/(?:api/|v\d+/)?(?:graphql|gql|query)(?:\?[^\s\"'<>]*)?",
    re.I,
)
OP_RE = re.compile(
    r"\b(query|mutation|subscription)\s*([A-Za-z_]\w*)?\s*(\([^)]*\))?\s*\{", re.I
)
FRAGMENT_RE = re.compile(r"\bfragment\s+([A-Za-z_]\w*)\s+on\s+[A-Za-z_]\w*\s*\{", re.I)
VAR_RE = re.compile(r"\$([A-Za-z_]\w*)\s*(?::\s*([\[\]!A-Za-z_][\[\]!A-Za-z_0-9]*))?")
OBJECT_IDS = {
    x.lower()
    for x in (
        "id",
        "userId",
        "accountId",
        "orgId",
        "organizationId",
        "tenantId",
        "teamId",
        "invoiceId",
        "projectId",
        "documentId",
        "fileId",
        "messageId",
        "paymentMethodId",
        "roleId",
        "permissionId",
        "ownerId",
        "memberId",
        "nodeId",
        "globalId",
    )
}
SENSITIVE = {
    x.lower()
    for x in (
        "email",
        "phone",
        "address",
        "fullName",
        "firstName",
        "lastName",
        "role",
        "roles",
        "permission",
        "permissions",
        "billing",
        "invoice",
        "payment",
        "paymentMethod",
        "card",
        "ssn",
        "dob",
        "birthDate",
        "token",
        "session",
        "secret",
        "apiKey",
        "admin",
        "internal",
        "tenant",
        "organization",
        "org",
        "user",
        "account",
        "owner",
        "member",
        "invite",
        "export",
        "file",
        "document",
    )
}
FIELD_RE = re.compile(
    r"(?m)(?:^|[{\n])\s*(?:[A-Za-z_]\w*\s*:\s*)?([A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*(?=[{@\n}]|\.\.\.)"
)
TYPE_RE = re.compile(r"\b(?:type|interface|input|enum|union|scalar)\s+([A-Za-z_]\w*)")
TYPE_BLOCK_RE = re.compile(
    r"\btype\s+(Query|Mutation|Subscription)\s*\{(.*?)\}", re.I | re.S
)
GLOBAL_ID_RE = re.compile(r"^(?:gid://|[A-Za-z0-9+/]{12,}={0,2}$)")


def _id(prefix: str, *parts: object) -> str:
    return f"{prefix}-{sha256('|'.join(map(str, parts)).encode()).hexdigest()[:12]}"


def _sensitive(name: str) -> bool:
    lower = name.lower()
    return lower in SENSITIVE or any(
        word in lower for word in SENSITIVE if len(word) > 4
    )


def _object_id(name: str) -> bool:
    return name.lower() in OBJECT_IDS or name.lower().endswith("id")


def _balanced(text: str, start: int) -> str:
    depth = 0
    quote = None
    escape = False
    for i in range(start, len(text)):
        char = text[i]
        if quote:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == quote:
                quote = None
            continue
        if char in "\"'`":
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return text[start:]


def _auth(headers: Any) -> list[str]:
    names = []
    if isinstance(headers, list):
        headers = {
            str(x.get("name", "")): str(x.get("value", ""))
            for x in headers
            if isinstance(x, dict)
        }
    if isinstance(headers, dict):
        for key, value in headers.items():
            lower = str(key).lower()
            if lower == "authorization":
                names.append(
                    "bearer token"
                    if str(value).lower().startswith("bearer ")
                    else "authorization header"
                )
            elif lower == "cookie":
                names.append("cookie auth")
            elif "csrf" in lower or "xsrf" in lower:
                names.append("CSRF token")
            elif "api" in lower and "key" in lower:
                names.append("API key")
    return sorted(set(names)) or ["unauthenticated observed"]


def _endpoint(
    url: str,
    source: Path,
    method: str = "UNKNOWN",
    auth: list[str] | None = None,
    evidence: str = "",
) -> GraphQLEndpoint:
    parsed = urlsplit(url)
    path = parsed.path or (url.split("?", 1)[0] if url.startswith("/") else "/graphql")
    clean = f"{parsed.scheme}://{parsed.netloc}{path}" if parsed.scheme else path
    return GraphQLEndpoint(
        id=_id("gql-endpoint", method.upper(), parsed.hostname or "", path),
        url=redact_text(clean),
        host=(parsed.hostname or "").lower(),
        path=path,
        method=method.upper(),
        source_type=source.suffix.lstrip(".") or "file",
        source_file=str(source),
        auth_indicators=auth or ["unknown"],
        risk_tags=["graphql", "manual-authorization-review"],
        redacted_evidence=redact_text(evidence or url),
    )


def _fields(document: str) -> list[str]:
    ignored = {
        "query",
        "mutation",
        "subscription",
        "fragment",
        "on",
        "true",
        "false",
        "null",
        "id",
    }
    without_variables = re.sub(r"\$[A-Za-z_]\w*", "", document)
    without_fragments = re.sub(r"\.\.\.[A-Za-z_]\w*", "", without_variables)
    return sorted(
        {
            value
            for value in re.findall(r"\b[A-Za-z_]\w*\b", without_fragments)
            if value.lower() not in ignored
            and value not in {"ID", "String", "Int", "Float", "Boolean"}
        }
    )


def _operation(
    document: str,
    match: re.Match[str],
    source: Path,
    endpoint_id: str = "",
    values: dict[str, Any] | None = None,
) -> GraphQLOperation:
    block = _balanced(document, document.find("{", match.start()))
    op_type = match.group(1).lower()
    name = match.group(2) or ""
    declarations = {
        m.group(1): m.group(2) or "" for m in VAR_RE.finditer(match.group(3) or "")
    }
    used = {m.group(1) for m in VAR_RE.finditer(block)} | set(declarations)
    fields = _fields(block)
    fragments = sorted(set(re.findall(r"\.\.\.([A-Za-z_]\w*)", block)))
    sensitive = sorted(x for x in fields if _sensitive(x))
    ids = sorted(x for x in used if _object_id(x))
    risk = {"manual-authorization-review"}
    combined = " ".join([name, *fields]).lower()
    if op_type == "mutation":
        risk.add("state-changing-mutation")
    for tag, words in {
        "admin-operation": ("admin",),
        "billing-operation": ("billing", "invoice", "payment"),
        "file-operation": (
            "file",
            "upload",
            "download",
            "delete",
            "export",
            "document",
        ),
        "tenant-boundary": ("tenant",),
        "org-boundary": ("organization", "org"),
        "role-boundary": ("role", "permission"),
    }.items():
        if any(word in combined for word in words):
            risk.add(tag)
    if ids:
        risk.add("object-id-candidate")
    if sensitive:
        risk.add("sensitive-field-selection")
    return GraphQLOperation(
        id=_id("gql-operation", source, op_type, name, match.start()),
        operation_type=op_type,
        operation_name=name,
        endpoint_id=endpoint_id,
        source_type=source.suffix.lstrip(".") or "text",
        source_file=str(source),
        variables=sorted(used),
        variable_types=declarations,
        fields=fields,
        fragments=fragments,
        sensitive_fields=sensitive,
        object_id_candidates=ids,
        risk_tags=sorted(risk),
        redacted_evidence=redact_text(block[:1200]),
    )


def _parse_documents(
    text: str, source: Path, endpoint_id: str = "", values: dict[str, Any] | None = None
) -> tuple[list[GraphQLOperation], list[GraphQLFragment]]:
    operations = [
        _operation(text, m, source, endpoint_id, values) for m in OP_RE.finditer(text)
    ]
    fragments = []
    for match in FRAGMENT_RE.finditer(text):
        block = _balanced(text, text.find("{", match.start()))
        fragments.append(
            GraphQLFragment(
                name=match.group(1),
                fields=_fields(block),
                source_file=str(source),
                redacted_evidence=redact_text(block[:1200]),
            )
        )
    return operations, fragments


def _schema_sdl(text: str, source: Path) -> GraphQLSchemaArtifact | None:
    types = sorted(set(TYPE_RE.findall(text)))
    roots: dict[str, list[str]] = {"query": [], "mutation": [], "subscription": []}
    for match in TYPE_BLOCK_RE.finditer(text):
        roots[match.group(1).lower()] = sorted(
            set(re.findall(r"(?m)^\s*([A-Za-z_]\w*)\s*(?:\(|:)", match.group(2)))
        )
    if not types and not any(roots.values()):
        return None
    fields = sorted({x for values in roots.values() for x in values})
    return GraphQLSchemaArtifact(
        id=_id("gql-schema", source, "sdl"),
        source_type=source.suffix.lstrip("."),
        source_file=str(source),
        artifact_type="schema_sdl",
        type_names=types,
        query_names=roots["query"],
        mutation_names=roots["mutation"],
        subscription_names=roots["subscription"],
        sensitive_types=sorted(x for x in types if _sensitive(x)),
        sensitive_fields=sorted(x for x in fields if _sensitive(x)),
        redacted_evidence=redact_text(text[:1600]),
    )


def _introspection(data: Any, source: Path) -> GraphQLSchemaArtifact | None:
    schema = data.get("data", data).get("__schema") if isinstance(data, dict) else None
    if not isinstance(schema, dict):
        return None
    types = [x for x in schema.get("types", []) if isinstance(x, dict)]
    names = sorted({str(x.get("name")) for x in types if x.get("name")})
    by_name = {str(x.get("name")): x for x in types}

    def root(kind: str) -> list[str]:
        root_name = (schema.get(f"{kind}Type") or {}).get("name")
        return sorted(
            str(x.get("name"))
            for x in by_name.get(str(root_name), {}).get("fields", [])
            if isinstance(x, dict) and x.get("name")
        )

    all_fields = sorted(
        {
            str(f.get("name"))
            for t in types
            for f in t.get("fields", []) or []
            if isinstance(f, dict) and f.get("name")
        }
    )
    return GraphQLSchemaArtifact(
        id=_id("gql-schema", source, "introspection"),
        source_type=source.suffix.lstrip("."),
        source_file=str(source),
        artifact_type="introspection_json",
        type_names=names,
        query_names=root("query"),
        mutation_names=root("mutation"),
        subscription_names=root("subscription"),
        sensitive_types=sorted(x for x in names if _sensitive(x)),
        sensitive_fields=sorted(x for x in all_fields if _sensitive(x)),
        redacted_evidence="Local __schema artifact (values omitted).",
    )


def _walk_payload(
    value: Any, source: Path, endpoint_id: str, inventory: GraphQLInventory
) -> None:
    if isinstance(value, list):
        gql = [x for x in value if isinstance(x, dict) and "query" in x]
        if len(gql) > 1:
            inventory.review_leads.append(
                _lead(
                    "batching_indicator",
                    "Observed GraphQL batch",
                    endpoint_id=endpoint_id,
                    reason=f"A local artifact contains {len(gql)} GraphQL operations in one request.",
                )
            )
        for child in value:
            _walk_payload(child, source, endpoint_id, inventory)
    elif isinstance(value, dict):
        if isinstance(value.get("query"), str):
            ops, fragments = _parse_documents(
                value["query"],
                source,
                endpoint_id,
                value.get("variables")
                if isinstance(value.get("variables"), dict)
                else {},
            )
            operation_name = str(value.get("operationName") or "")
            if operation_name and ops:
                for op in ops:
                    if not op.operation_name:
                        op.operation_name = operation_name
            inventory.operations.extend(ops)
            inventory.fragments.extend(fragments)
        if isinstance(value.get("errors"), list):
            raw = json.dumps(value.get("errors"))
            if re.search(
                r"stack|trace|resolver|extensions|locations|path|exception", raw, re.I
            ):
                inventory.review_leads.append(
                    _lead(
                        "excessive_error_detail",
                        "Verbose GraphQL error details",
                        endpoint_id=endpoint_id,
                        severity="low",
                        reason="Captured errors include resolver, path, location, extension, exception, or stack details.",
                        evidence=raw,
                    )
                )
        for child in value.values():
            _walk_payload(child, source, endpoint_id, inventory)


def _lead(
    category: str,
    title: str,
    *,
    endpoint_id: str = "",
    operation_id: str = "",
    severity: str = "info",
    reason: str = "",
    questions: list[str] | None = None,
    evidence: str = "",
) -> GraphQLReviewLead:
    return GraphQLReviewLead(
        id=_id("gql-lead", category, endpoint_id, operation_id, title),
        category=category,
        title=title,
        endpoint_id=endpoint_id,
        operation_id=operation_id,
        severity=severity,
        confidence=Confidence.MEDIUM,
        reason=reason,
        manual_questions=questions or [],
        redacted_evidence=redact_text(evidence[:1200]),
    )


def _derive(inventory: GraphQLInventory) -> None:
    seen_vars: dict[str, GraphQLVariable] = {}
    for op in inventory.operations:
        for name in op.variables:
            tags = []
            if _object_id(name):
                tags.append("object-id-candidate")
            if _sensitive(name):
                tags.append("sensitive-name")
            seen_vars.setdefault(
                name,
                GraphQLVariable(
                    name=name,
                    value_type=op.variable_types.get(name, ""),
                    sensitive=_sensitive(name),
                    object_id_candidate=_object_id(name),
                    risk_tags=tags,
                ),
            )
        if op.object_id_candidates:
            inventory.review_leads.append(
                _lead(
                    "idor_bola_candidate",
                    f"Object ID variables in {op.operation_name or op.operation_type.value}",
                    endpoint_id=op.endpoint_id,
                    operation_id=op.id,
                    severity="medium"
                    if op.operation_type.value == "mutation"
                    else "low",
                    reason=f"Observed object identifier variables: {', '.join(op.object_id_candidates)}.",
                    questions=[
                        "Can Actor A access an object owned by Actor B using the observed object ID variable?"
                    ],
                )
            )
        if op.sensitive_fields:
            inventory.review_leads.append(
                _lead(
                    "sensitive_field_exposure",
                    f"Sensitive fields selected by {op.operation_name or op.operation_type.value}",
                    endpoint_id=op.endpoint_id,
                    operation_id=op.id,
                    severity="low",
                    reason=f"Selected fields need role and ownership review: {', '.join(op.sensitive_fields)}.",
                    questions=[
                        "Are sensitive fields filtered by role and object ownership?"
                    ],
                )
            )
        if op.operation_type.value == "mutation":
            inventory.review_leads.append(
                _lead(
                    "state_changing_mutation",
                    f"State-changing mutation: {op.operation_name or 'unnamed'}",
                    endpoint_id=op.endpoint_id,
                    operation_id=op.id,
                    severity="medium",
                    reason="Mutations change server-side state and require manual authorization review.",
                    questions=[
                        "Can a lower-privileged actor run this mutation directly?"
                    ],
                )
            )
        mapping = {
            "admin-operation": "admin_operation",
            "billing-operation": "billing_operation",
            "file-operation": "file_operation",
            "tenant-boundary": "tenant_boundary",
            "org-boundary": "org_boundary",
            "role-boundary": "role_boundary",
        }
        for tag, category in mapping.items():
            if tag in op.risk_tags:
                inventory.review_leads.append(
                    _lead(
                        category,
                        f"{tag.replace('-', ' ').title()}: {op.operation_name or op.operation_type.value}",
                        endpoint_id=op.endpoint_id,
                        operation_id=op.id,
                        severity="low",
                        reason=f"Observed operation names or fields indicate {tag.replace('-', ' ')} review.",
                    )
                )
    inventory.variables = sorted(seen_vars.values(), key=lambda x: x.name.lower())
    for artifact in inventory.schema_artifacts:
        inventory.review_leads.append(
            _lead(
                "introspection_artifact",
                "Local GraphQL schema/introspection artifact",
                severity="low"
                if artifact.sensitive_fields or artifact.sensitive_types
                else "info",
                reason="A locally captured schema artifact can guide authorized manual review.",
                evidence=artifact.redacted_evidence,
            )
        )
    unique = {}
    for lead in inventory.review_leads:
        unique[lead.id] = lead
    inventory.review_leads = list(unique.values())
    inventory.summary = {
        "sources_analyzed": len(inventory.source_files),
        "endpoints": len(inventory.endpoints),
        "operations": len(inventory.operations),
        "variables": len(inventory.variables),
        "fragments": len(inventory.fragments),
        "schema_artifacts": len(inventory.schema_artifacts),
        "review_leads": len(inventory.review_leads),
        "mode": "passive/local-only",
    }


def _scan(path: Path, inventory: GraphQLInventory) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"Could not read input file {path}: {exc}") from exc
    inventory.source_files.append(str(path))
    data = None
    if path.suffix.lower() in {".json", ".har"}:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in {path}: {exc}") from exc
    elif path.suffix.lower() in {".yml", ".yaml"}:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML in {path}: {exc}") from exc
    if path.suffix.lower() == ".har":
        entries = data.get("log", {}).get("entries") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            raise ValueError("HAR must contain a log.entries list")
        for entry in entries:
            request = entry.get("request", {}) if isinstance(entry, dict) else {}
            response = entry.get("response", {}) if isinstance(entry, dict) else {}
            url, method = (
                str(request.get("url", "")),
                str(request.get("method", "UNKNOWN")),
            )
            endpoint = None
            if ENDPOINT_RE.search(url):
                endpoint = _endpoint(
                    url, path, method, _auth(request.get("headers")), url
                )
                inventory.endpoints.append(endpoint)
            post = request.get("postData", {}) if isinstance(request, dict) else {}
            body = post.get("text", "") if isinstance(post, dict) else ""
            if body:
                try:
                    payload = json.loads(body)
                except (json.JSONDecodeError, TypeError):
                    payload = {"query": body} if OP_RE.search(str(body)) else body
                _walk_payload(payload, path, endpoint.id if endpoint else "", inventory)
            content = response.get("content", {}) if isinstance(response, dict) else {}
            response_text = content.get("text", "") if isinstance(content, dict) else ""
            if response_text:
                with suppress(json.JSONDecodeError, TypeError):
                    _walk_payload(
                        json.loads(response_text),
                        path,
                        endpoint.id if endpoint else "",
                        inventory,
                    )
    else:
        for match in ENDPOINT_RE.finditer(text):
            inventory.endpoints.append(
                _endpoint(match.group(0), path, evidence=match.group(0))
            )
        ops, fragments = _parse_documents(
            text, path, inventory.endpoints[0].id if inventory.endpoints else ""
        )
        inventory.operations.extend(ops)
        inventory.fragments.extend(fragments)
        if data is not None:
            artifact = _introspection(data, path)
            if artifact:
                inventory.schema_artifacts.append(artifact)
            _walk_payload(
                data,
                path,
                inventory.endpoints[0].id if inventory.endpoints else "",
                inventory,
            )
        artifact = _schema_sdl(text, path)
        if artifact:
            inventory.schema_artifacts.append(artifact)


def _merge_endpoints(items: list[GraphQLEndpoint]) -> list[GraphQLEndpoint]:
    merged = {}
    for item in items:
        key = (item.method, item.host, item.path)
        if key in merged:
            merged[key].occurrences += 1
            merged[key].auth_indicators = sorted(
                set(merged[key].auth_indicators + item.auth_indicators)
            )
        else:
            merged[key] = item
    return list(merged.values())


def scan_file(path: Path) -> GraphQLInventory:
    if not path.is_file():
        raise ValueError(f"Input file does not exist: {path}")
    if path.suffix.lower() not in SUPPORTED:
        raise ValueError(f"Unsupported input type: {path.suffix or '<none>'}")
    inv = GraphQLInventory()
    _scan(path, inv)
    inv.endpoints = _merge_endpoints(inv.endpoints)
    _derive(inv)
    return inv


def scan_folder(path: Path) -> GraphQLInventory:
    if not path.is_dir():
        raise ValueError(f"Input folder does not exist: {path}")
    inv = GraphQLInventory()
    for item in sorted(
        x for x in path.rglob("*") if x.is_file() and x.suffix.lower() in SUPPORTED
    ):
        _scan(item, inv)
    inv.source_files = sorted(set(inv.source_files))
    inv.endpoints = _merge_endpoints(inv.endpoints)
    _derive(inv)
    return inv


def load_or_scan(path: Path) -> GraphQLInventory:
    if path.is_dir():
        return scan_folder(path)
    if path.suffix.lower() == ".json":
        try:
            data = json.loads(path.read_text())
            if isinstance(data, dict) and {
                "endpoints",
                "operations",
                "schema_artifacts",
                "review_leads",
            } <= set(data):
                return GraphQLInventory.model_validate(data)
        except (OSError, json.JSONDecodeError, ValidationError):
            pass
    return scan_file(path)


def checklist(inventory: GraphQLInventory) -> dict[str, list[str]]:
    sections = {
        "Endpoint access review": [
            "Are observed GraphQL endpoints protected consistently for authenticated and unauthenticated actors?"
        ],
        "Query authorization review": [
            "Can Actor A query an object owned by Actor B using the observed object ID variable?"
        ],
        "Mutation authorization review": [
            "Can a lower-privileged actor run each observed mutation directly?"
        ],
        "Object ID / BOLA review": [
            "Are object ID variables authorized by ownership, not merely accepted as valid identifiers?"
        ],
        "Tenant/org boundary review": [
            "Are tenantId/orgId variables enforced server-side or trusted from the request?"
        ],
        "Role/permission review": [
            "Are admin-like operations protected server-side, not only hidden in the UI?"
        ],
        "Sensitive field exposure review": [
            "Are sensitive fields filtered by role and object ownership?"
        ],
        "File/upload/export review": [
            "Do file and export operations enforce ownership and least privilege?"
        ],
        "Billing/payment review": [
            "Do billing and payment operations enforce account and organization boundaries?"
        ],
        "Introspection/schema artifact review": [
            "Does the local schema artifact reveal sensitive operations that require manual authorization review?"
        ],
        "Batching/error detail review": [
            "Are batch requests authorized per operation?",
            "Do GraphQL errors expose resolver names, stack traces, internal paths, or schema details?",
        ],
    }
    return sections


def render_checklist(inventory: GraphQLInventory, format: str = "markdown") -> str:
    data = checklist(inventory)
    if format == "json":
        return json.dumps(data, indent=2)
    if format != "markdown":
        raise ValueError("Checklist format must be markdown or json")
    return (
        "# GraphQL Manual Testing Checklist\n\n"
        + "\n\n".join(
            f"## {name}\n\n" + "\n".join(f"- [ ] {q}" for q in questions)
            for name, questions in data.items()
        )
        + "\n\n> Manual, authorized review only. No requests or payloads are generated.\n"
    )


def render_json(inventory: GraphQLInventory) -> str:
    data = inventory.model_dump(mode="json")
    for collection in (
        "endpoints",
        "operations",
        "fragments",
        "schema_artifacts",
        "review_leads",
    ):
        for item in data[collection]:
            item["evidence"] = ""
            item["redacted_evidence"] = redact_text(item.get("redacted_evidence", ""))
    return json.dumps(data, indent=2)


def render_markdown(inventory: GraphQLInventory) -> str:
    def bullets(values: list[str]) -> str:
        return "\n".join(f"- {redact_text(x)}" for x in values) or "_None observed._"

    endpoints = [
        f"`{x.method}` `{x.url or x.path}` — {', '.join(x.auth_indicators)}"
        for x in inventory.endpoints
    ]
    operations = [
        f"**{x.operation_type.value} {x.operation_name or '(unnamed)'}** — fields: {', '.join(x.fields) or 'none'}; tags: {', '.join(x.risk_tags)}"
        for x in inventory.operations
    ]
    variables = [
        f"`${x.name}` ({x.value_type or 'type unknown'}) — object ID: {'yes' if x.object_id_candidate else 'no'}"
        for x in inventory.variables
    ]
    sensitive = sorted({f for x in inventory.operations for f in x.sensitive_fields})
    fragments = [f"**{x.name}** — {', '.join(x.fields)}" for x in inventory.fragments]
    schemas = [
        f"**{x.artifact_type.value}** `{x.source_file}` — types: {', '.join(x.type_names) or 'none'}"
        for x in inventory.schema_artifacts
    ]
    leads = [
        f"**{x.severity.value.title()} — {x.title}**: {x.reason}"
        for x in inventory.review_leads
    ]
    return redact_text(f"""# GraphQL Risk Mapper Report

## Summary

- Sources: {len(inventory.source_files)}
- Endpoints: {len(inventory.endpoints)}
- Operations: {len(inventory.operations)}
- Review leads: {len(inventory.review_leads)}
- Mode: passive/local-only

## Sources analyzed

{bullets(inventory.source_files)}

## GraphQL endpoints

{bullets(endpoints)}

## Operations inventory

{bullets(operations)}

## Variables and object-ID candidates

{bullets(variables)}

## Sensitive fields

{bullets(sensitive)}

## Fragments

{bullets(fragments)}

## Schema/introspection artifacts

{bullets(schemas)}

## Review leads

{bullets(leads)}

## Manual testing checklist

{render_checklist(inventory)}

## Redaction notice

Captured values, credentials, cookies, tokens, PII, and authorization material are redacted by default. Reports retain operation, field, and variable names needed for manual review.

## Limitations

This passive mapper reads local artifacts only. It does not send or replay requests, run introspection, fuzz, generate payloads, bypass controls, validate vulnerabilities, or test GraphQL depth, complexity, batching abuse, or denial of service.
""")
