"""Passive endpoint extraction and normalization."""

import json
import re
from contextlib import suppress
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from bugbounty_scout.models import ApiInventory, Endpoint, EndpointSource
from bugbounty_scout.redaction import redact_text

SUPPORTED_SUFFIXES = {".har", ".js", ".html", ".htm", ".json", ".txt"}
STATIC_SUFFIXES = {
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".svg",
    ".woff",
    ".woff2",
    ".map",
}
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I
)
ABSOLUTE_RE = re.compile(r"""(?P<url>(?:https?|wss?)://[^\s"'<>\\)]+)""", re.I)
PATH_RE = re.compile(
    r"""(?P<quote>["'])(?P<path>/(?:api|v\d+|graphql|admin|auth|upload|files?|"""
    r"""exports?|users?|accounts?|orgs?|organizations?|projects?|billing|invoices?|"""
    r"""internal|debug|search)[^"' <>{}\\]*)(?P=quote)""",
    re.I,
)
CALL_RE = re.compile(
    r"""(?P<call>fetch|axios(?:\.(?P<verb>get|post|put|patch|delete))?|"""
    r"""new\s+WebSocket|new\s+EventSource)\s*\(\s*["'](?P<url>[^"']+)["']""",
    re.I,
)
OBJECT_NAMES = {
    name.lower(): name
    for name in (
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
    )
}


def normalize_path(path: str) -> str:
    """Normalize likely object identifiers while preserving static assets."""
    clean = path or "/"
    if Path(clean).suffix.lower() in STATIC_SUFFIXES:
        return clean
    parts = clean.split("/")
    resource_words = {
        "users",
        "accounts",
        "orgs",
        "organizations",
        "tenants",
        "teams",
        "invoices",
        "projects",
        "documents",
        "files",
        "messages",
        "roles",
        "permissions",
        "members",
        "payment-methods",
    }
    for index, part in enumerate(parts):
        if not part or part.startswith("{"):
            continue
        if UUID_RE.fullmatch(part):
            parts[index] = "{uuid}"
        elif part.isdigit():
            parts[index] = "{id}"
        elif (
            index
            and parts[index - 1].lower() in resource_words
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{2,}", part)
        ):
            parts[index] = "{slug}"
    return "/".join(parts) or "/"


def _json_keys(value: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            keys.add(str(key))
            keys.update(_json_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.update(_json_keys(child))
    return keys


def _auth(headers: dict[str, str], cookies: bool = False) -> list[str]:
    found: set[str] = set()
    for name, value in headers.items():
        lowered = name.lower()
        if lowered == "authorization":
            if value.lower().startswith("bearer "):
                found.add("bearer token")
            elif value.lower().startswith("basic "):
                found.add("basic auth")
        if "api" in lowered and "key" in lowered:
            found.add("API key")
        if "csrf" in lowered or "xsrf" in lowered:
            found.add("CSRF token")
        if lowered == "cookie":
            found.add("cookie auth")
    if cookies:
        found.add("cookie auth")
    return sorted(found or {"unauthenticated observed"})


def _candidates(path: str, names: set[str]) -> list[str]:
    found = {
        OBJECT_NAMES[name.lower()] for name in names if name.lower() in OBJECT_NAMES
    }
    found.update(re.findall(r"\{(?:id|uuid|slug)\}", normalize_path(path)))
    return sorted(found)


def _tags(path: str, method: str, candidates: list[str], scheme: str) -> list[str]:
    text = path.lower()
    tags = set()
    patterns = {
        "auth": ("auth", "login", "logout", "token", "session"),
        "admin": ("admin",),
        "billing": ("billing", "invoice", "payment"),
        "user-profile": ("profile", "/users"),
        "file-upload": ("upload",),
        "file-download": ("download",),
        "export": ("export",),
        "invite": ("invite",),
        "organization-management": ("organization", "/orgs", "/tenant"),
        "permission-management": ("permission",),
        "role-management": ("role",),
        "password-reset": ("password/reset", "reset-password", "forgot-password"),
        "graphql": ("graphql",),
        "search": ("search",),
        "debug": ("debug",),
        "internal": ("internal",),
        "sensitive-data": ("billing", "invoice", "payment", "profile", "document"),
    }
    for tag, needles in patterns.items():
        if any(needle in text for needle in needles):
            tags.add(tag)
    if scheme in {"ws", "wss"}:
        tags.add("websocket")
    if candidates:
        tags.add("idor-candidate")
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        tags.add("state-changing")
    return sorted(tags)


def _make_endpoint(
    raw_url: str,
    source_file: Path,
    *,
    method: str = "UNKNOWN",
    line: int | None = None,
    query_names: set[str] | None = None,
    body_params: set[str] | None = None,
    json_keys: set[str] | None = None,
    header_names: set[str] | None = None,
    status_codes: set[int] | None = None,
    mime_types: set[str] | None = None,
    auth_indicators: list[str] | None = None,
    evidence: str = "",
) -> Endpoint:
    parsed = urlsplit(raw_url)
    path = parsed.path or (raw_url.split("?", 1)[0] if raw_url.startswith("/") else "/")
    scheme, host = parsed.scheme.lower(), (parsed.hostname or "").lower()
    query = set(query_names or ())
    query.update(name for name, _ in parse_qsl(parsed.query, keep_blank_values=True))
    names = query | set(body_params or ()) | set(json_keys or ())
    candidates = _candidates(path, names)
    normalized = normalize_path(path)
    key = f"{method.upper()}|{host}|{normalized}"
    redacted = redact_text(evidence or raw_url)
    return Endpoint(
        id=f"ep-{sha256(key.encode()).hexdigest()[:12]}",
        method=method.upper(),
        scheme=scheme,
        host=host,
        path=path,
        normalized_path=normalized,
        url=(f"{scheme}://{parsed.netloc}{path}" if scheme else path),
        query_params=sorted(query),
        body_params=sorted(body_params or ()),
        json_keys=sorted(json_keys or ()),
        header_names=sorted(header_names or ()),
        status_codes=sorted(status_codes or ()),
        mime_types=sorted(mime_types or ()),
        source=[
            EndpointSource(
                type=source_file.suffix.lower().lstrip(".") or "file",
                file=str(source_file),
                url=redact_text(raw_url),
                line=line,
                evidence="",
                redacted_evidence=redacted,
            )
        ],
        source_file=str(source_file),
        auth_indicators=auth_indicators or ["unknown"],
        object_id_candidates=candidates,
        risk_tags=_tags(path, method.upper(), candidates, scheme),
    )


def extract_har(path: Path) -> list[Endpoint]:
    """Extract endpoint metadata from a local HAR capture."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        entries = data["log"]["entries"]
    except OSError as exc:
        raise ValueError(f"Could not read input file {path}: {exc}") from exc
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError(f"Invalid HAR file {path}: {exc}") from exc
    results = []
    for raw in entries:
        request, response = raw.get("request", {}), raw.get("response", {})
        url = str(request.get("url", ""))
        req_headers = {
            str(item.get("name", "")): str(item.get("value", ""))
            for item in request.get("headers", [])
        }
        response_headers = {
            str(item.get("name", "")): str(item.get("value", ""))
            for item in response.get("headers", [])
        }
        post = request.get("postData", {}) or {}
        body_names = {
            str(item.get("name")) for item in post.get("params", []) if item.get("name")
        }
        request_keys: set[str] = set()
        response_keys: set[str] = set()
        for text, target in (
            (post.get("text", ""), request_keys),
            ((response.get("content", {}) or {}).get("text", ""), response_keys),
        ):
            with suppress(json.JSONDecodeError, TypeError):
                target.update(_json_keys(json.loads(text)))
        results.append(
            _make_endpoint(
                url,
                path,
                method=str(request.get("method", "UNKNOWN")),
                query_names={
                    str(item.get("name"))
                    for item in request.get("queryString", [])
                    if item.get("name")
                },
                body_params=body_names,
                json_keys=request_keys | response_keys,
                header_names=set(req_headers) | set(response_headers),
                status_codes={int(response.get("status", 0))},
                mime_types={
                    str((response.get("content", {}) or {}).get("mimeType", "unknown"))
                },
                auth_indicators=_auth(req_headers, bool(request.get("cookies"))),
                evidence=url,
            )
        )
    return results


def extract_text(path: Path) -> list[Endpoint]:
    """Conservatively extract endpoint-like strings from frontend or text files."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Could not read input file {path}: {exc}") from exc
    if not text.strip():
        return []
    return extract_text_content(path, text)


def extract_text_content(path: Path, text: str) -> list[Endpoint]:
    """Extract endpoint-like strings from supplied local text content."""
    found: list[tuple[str, str, int]] = []
    occupied: set[str] = set()
    for match in CALL_RE.finditer(text):
        call, raw = match.group("call").lower(), match.group("url")
        method = (
            match.group("verb") or ("GET" if "eventsource" in call else "UNKNOWN")
        ).upper()
        found.append((raw, method, text.count("\n", 0, match.start()) + 1))
        occupied.add(raw)
    for regex in (ABSOLUTE_RE, PATH_RE):
        for match in regex.finditer(text):
            raw = (
                match.group("url")
                if "url" in match.groupdict()
                else match.group("path")
            )
            if raw not in occupied:
                found.append((raw, "UNKNOWN", text.count("\n", 0, match.start()) + 1))
                occupied.add(raw)
    form_names = set(
        re.findall(r"""(?:name|data-param)=["']([A-Za-z][\w.-]*)["']""", text, re.I)
    )
    likely_names = {
        name
        for name in re.findall(r"""["']([A-Za-z][A-Za-z0-9_]*(?:Id|_id))["']""", text)
    }
    return [
        _make_endpoint(
            raw,
            path,
            method=method,
            line=line,
            body_params=form_names
            if path.suffix.lower() in {".html", ".htm"}
            else set(),
            json_keys=likely_names,
            evidence=raw,
        )
        for raw, method, line in found
    ]


def _merge(endpoints: list[Endpoint], source_files: list[str]) -> ApiInventory:
    grouped: dict[tuple[str, str, str], Endpoint] = {}
    for endpoint in endpoints:
        key = (endpoint.method, endpoint.host, endpoint.normalized_path)
        if key not in grouped:
            grouped[key] = endpoint
            continue
        current = grouped[key]
        current.occurrences += endpoint.occurrences
        current.source.extend(endpoint.source)
        for field in (
            "query_params",
            "body_params",
            "json_keys",
            "header_names",
            "status_codes",
            "mime_types",
            "risk_tags",
            "auth_indicators",
            "object_id_candidates",
        ):
            setattr(
                current,
                field,
                sorted(set(getattr(current, field)) | set(getattr(endpoint, field))),
            )
    values = sorted(
        grouped.values(),
        key=lambda item: (item.host, item.normalized_path, item.method),
    )
    return ApiInventory(
        endpoints=values,
        hosts=sorted({item.host for item in values if item.host}),
        source_files=sorted(source_files),
        summary={
            "endpoint_count": len(values),
            "host_count": len({item.host for item in values if item.host}),
            "high_interest_count": sum(bool(item.risk_tags) for item in values),
        },
    )


def inventory_from_file(path: Path) -> ApiInventory:
    if not path.is_file():
        raise ValueError(f"Input file does not exist: {path}")
    if path.suffix.lower() not in SUPPORTED_SUFFIXES:
        raise ValueError(f"Unsupported input type: {path.suffix or '<none>'}")
    endpoints = (
        extract_har(path) if path.suffix.lower() == ".har" else extract_text(path)
    )
    return _merge(endpoints, [str(path)])


def inventory_from_folder(path: Path) -> ApiInventory:
    if not path.is_dir():
        raise ValueError(f"Input folder does not exist: {path}")
    files = sorted(
        item
        for item in path.rglob("*")
        if item.is_file() and item.suffix.lower() in SUPPORTED_SUFFIXES
    )
    endpoints: list[Endpoint] = []
    for file in files:
        endpoints.extend(
            extract_har(file) if file.suffix.lower() == ".har" else extract_text(file)
        )
    return _merge(endpoints, [str(file) for file in files])


def load_inventory(path: Path) -> ApiInventory:
    return inventory_from_folder(path) if path.is_dir() else inventory_from_file(path)
