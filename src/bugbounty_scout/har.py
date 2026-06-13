"""Passive, local-only HAR analysis with redacted-by-default output."""

import json
import re
from collections import Counter
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, Field

from bugbounty_scout.models import Finding
from bugbounty_scout.redaction import redact_text

SENSITIVE_NAME_RE = re.compile(
    r"(?i)(?:api[_-]?key|authorization|auth|bearer|csrf|xsrf|oauth|code|"
    r"refresh[_-]?token|access[_-]?token|secret|password|passwd|session|token)"
)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(
    r"(?<!\w)(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?"
    r"\d{3}[-.\s]?\d{4}(?!\w)"
)
BEARER_RE = re.compile(r"(?i)\bbearer\s+\S+")
API_KEY_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|apikey|client[_-]?secret|access[_-]?token|"
    r"refresh[_-]?token)\b\s*[=:]\s*[\"']?[^\"'\s,;&}]+"
)
SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "x-content-type-options",
    "cache-control",
    "pragma",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-headers",
    "access-control-allow-methods",
)


class HarEntry(BaseModel):
    method: str
    url: str
    status: int
    request_headers: dict[str, str] = Field(default_factory=dict)
    response_headers: dict[str, str] = Field(default_factory=dict)
    mime_type: str = ""


class HarSummary(BaseModel):
    entry_count: int
    methods: dict[str, int]
    status_codes: dict[str, int]
    mime_types: dict[str, int]
    entries: list[HarEntry]


class Endpoint(BaseModel):
    method: str
    url: str
    host: str
    path: str
    query_parameters: list[str] = Field(default_factory=list)
    status_codes: list[int] = Field(default_factory=list)
    mime_types: list[str] = Field(default_factory=list)
    count: int = 1


class SensitiveMaterial(BaseModel):
    category: str
    location: str
    source_url: str
    name: str = ""
    redacted_value: str


class CookieReview(BaseModel):
    name: str
    source: str
    source_url: str
    cookie_type: str
    redacted_value: str = "<redacted-cookie>"
    secure: bool = False
    http_only: bool = False
    same_site: str = ""
    domain: str = ""
    path: str = ""
    expires: str = ""
    max_age: str = ""
    observations: list[str] = Field(default_factory=list)


class HeaderReview(BaseModel):
    source_url: str
    header: str
    value: str
    classification: str
    observation: str


class ThirdPartyReview(BaseModel):
    host: str
    request_count: int
    methods: list[str]
    sensitive_categories: list[str]
    source_urls: list[str]


class CacheReview(BaseModel):
    source_url: str
    classification: str = "needs manual review"
    observation: str
    cache_control: str = ""


class HarAnalysis(BaseModel):
    source: str
    primary_host: str
    summary: HarSummary
    endpoints: list[Endpoint]
    sensitive_material: list[SensitiveMaterial]
    cookies: list[CookieReview]
    headers: list[HeaderReview]
    third_parties: list[ThirdPartyReview]
    cache_review: list[CacheReview]
    findings: list[Finding]


def _load_har(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not path.is_file():
        raise ValueError(f"HAR file does not exist: {path}")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Could not read HAR file {path}: {exc}") from exc
    if not text.strip():
        raise ValueError(f"HAR file is empty: {path}")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in HAR file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("HAR root must be a JSON object")
    raw_entries = data.get("log", {}).get("entries")
    if not isinstance(raw_entries, list):
        raise ValueError("HAR must contain a log.entries list")
    if any(not isinstance(entry, dict) for entry in raw_entries):
        raise ValueError("Every HAR log.entries item must be an object")
    return data, raw_entries


def _items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _headers(items: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in _items(items):
        name = str(item.get("name", "")).strip()
        if name:
            result[name] = str(item.get("value", ""))
    return result


def _header(headers: dict[str, str], name: str) -> str:
    return next(
        (value for key, value in headers.items() if key.lower() == name.lower()), ""
    )


def _request_response(raw: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    request = raw.get("request")
    response = raw.get("response")
    if not isinstance(request, dict) or not isinstance(response, dict):
        raise ValueError("Every HAR entry must contain request and response objects")
    return request, response


def parse_har(path: Path) -> HarSummary:
    """Load a HAR file and extract summary metadata."""
    _, raw_entries = _load_har(path)
    entries: list[HarEntry] = []
    for raw in raw_entries:
        request, response = _request_response(raw)
        content = response.get("content")
        content = content if isinstance(content, dict) else {}
        try:
            status = int(response.get("status", 0))
        except (TypeError, ValueError) as exc:
            raise ValueError("HAR response status must be an integer") from exc
        entries.append(
            HarEntry(
                method=str(request.get("method", "")).upper(),
                url=str(request.get("url", "")),
                status=status,
                request_headers=_headers(request.get("headers")),
                response_headers=_headers(response.get("headers")),
                mime_type=str(content.get("mimeType", "")),
            )
        )
    methods = Counter(entry.method for entry in entries)
    statuses = Counter(str(entry.status) for entry in entries)
    mimes = Counter(entry.mime_type or "unknown" for entry in entries)
    return HarSummary(
        entry_count=len(entries),
        methods=dict(sorted(methods.items())),
        status_codes=dict(sorted(statuses.items())),
        mime_types=dict(sorted(mimes.items())),
        entries=entries,
    )


def extract_endpoints(path: Path) -> list[Endpoint]:
    """Return normalized endpoints, combining duplicate method/host/path entries."""
    summary = parse_har(path)
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for entry in summary.entries:
        parsed = urlsplit(entry.url)
        host = (parsed.hostname or "").lower()
        endpoint_path = parsed.path or "/"
        key = (entry.method, host, endpoint_path)
        item = grouped.setdefault(
            key,
            {
                "method": entry.method,
                "url": f"{parsed.scheme}://{parsed.netloc}{endpoint_path}",
                "host": host,
                "path": endpoint_path,
                "query_parameters": set(),
                "status_codes": set(),
                "mime_types": set(),
                "count": 0,
            },
        )
        item["query_parameters"].update(name for name, _ in parse_qsl(parsed.query))
        item["status_codes"].add(entry.status)
        item["mime_types"].add(entry.mime_type or "unknown")
        item["count"] += 1
    return [
        Endpoint(
            **{
                **item,
                "query_parameters": sorted(item["query_parameters"]),
                "status_codes": sorted(item["status_codes"]),
                "mime_types": sorted(item["mime_types"]),
            }
        )
        for _, item in sorted(grouped.items())
    ]


def _categories(name: str, value: str) -> set[str]:
    categories: set[str] = set()
    lowered = name.lower()
    combined = f"{name}={value}"
    if "authorization" in lowered and BEARER_RE.search(value):
        categories.add("bearer_token")
    if JWT_RE.search(value):
        categories.add("jwt")
    if "api" in lowered and "key" in lowered or API_KEY_RE.search(combined):
        categories.add("api_key")
    if "session" in lowered:
        categories.add("session")
    if "csrf" in lowered or "xsrf" in lowered:
        categories.add("csrf_token")
    if ("oauth" in lowered and "code" in lowered) or lowered in {
        "code",
        "authorization_code",
    }:
        categories.add("oauth_authorization_code")
    if "refresh" in lowered and "token" in lowered:
        categories.add("refresh_token")
    if EMAIL_RE.search(value):
        categories.add("email")
    if PHONE_RE.search(value):
        categories.add("phone_number")
    if SENSITIVE_NAME_RE.search(name) and value:
        categories.add("sensitive_key_value")
    return categories


def _redacted_value(category: str) -> str:
    return f"<redacted-{category.replace('_', '-')}>"


def _scan(
    findings: list[SensitiveMaterial],
    *,
    name: str,
    value: str,
    location: str,
    source_url: str,
) -> None:
    for category in sorted(_categories(name, value)):
        findings.append(
            SensitiveMaterial(
                category=category,
                location=location,
                source_url=redact_text(source_url),
                name=name,
                redacted_value=_redacted_value(category),
            )
        )


def _scan_structured_body(
    findings: list[SensitiveMaterial],
    body: str,
    *,
    location: str,
    source_url: str,
) -> None:
    """Scan common JSON/form key-value bodies while retaining no raw values."""
    try:
        decoded = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        decoded = None

    def walk(value: Any, name: str = "") -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                walk(item, str(key))
        elif isinstance(value, list):
            for item in value:
                walk(item, name)
        elif name:
            _scan(
                findings,
                name=name,
                value=str(value),
                location=location,
                source_url=source_url,
            )

    if decoded is not None:
        walk(decoded)
    else:
        for name, value in parse_qsl(body, keep_blank_values=True):
            _scan(
                findings,
                name=name,
                value=value,
                location=location,
                source_url=source_url,
            )


def detect_sensitive_material(path: Path) -> list[SensitiveMaterial]:
    """Identify sensitive material locations without retaining detected values."""
    _, entries = _load_har(path)
    findings: list[SensitiveMaterial] = []
    for raw in entries:
        request, response = _request_response(raw)
        url = str(request.get("url", ""))
        parsed = urlsplit(url)
        _scan(
            findings,
            name="request_url",
            value=url,
            location="request URL",
            source_url=url,
        )
        for name, value in parse_qsl(parsed.query, keep_blank_values=True):
            _scan(
                findings,
                name=name,
                value=value,
                location="query parameter",
                source_url=url,
            )
        for item in _items(request.get("queryString")):
            _scan(
                findings,
                name=str(item.get("name", "")),
                value=str(item.get("value", "")),
                location="query parameter",
                source_url=url,
            )
        for side, obj in (("request", request), ("response", response)):
            for item in _items(obj.get("headers")):
                name, value = str(item.get("name", "")), str(item.get("value", ""))
                _scan(
                    findings,
                    name=name,
                    value=value,
                    location=f"{side} header",
                    source_url=url,
                )
            for item in _items(obj.get("cookies")):
                _scan(
                    findings,
                    name=str(item.get("name", "")),
                    value=str(item.get("value", "")),
                    location="cookie",
                    source_url=url,
                )
        post_data = request.get("postData")
        if isinstance(post_data, dict):
            body = str(post_data.get("text", ""))
            _scan(
                findings,
                name="request_body",
                value=body,
                location="request body",
                source_url=url,
            )
            _scan_structured_body(
                findings,
                body,
                location="request body",
                source_url=url,
            )
            for item in _items(post_data.get("params")):
                _scan(
                    findings,
                    name=str(item.get("name", "")),
                    value=str(item.get("value", "")),
                    location="request body",
                    source_url=url,
                )
        content = response.get("content")
        if isinstance(content, dict):
            response_body = str(content.get("text", ""))
            _scan(
                findings,
                name="response_body",
                value=response_body,
                location="response body",
                source_url=url,
            )
            _scan_structured_body(
                findings,
                response_body,
                location="response body",
                source_url=url,
            )
    unique = {
        (item.category, item.location, item.source_url, item.name): item
        for item in findings
    }
    return list(unique.values())


def _cookie_type(name: str) -> str:
    lowered = name.lower()
    if any(word in lowered for word in ("session", "sid", "sess")):
        return "session"
    if any(word in lowered for word in ("auth", "token", "jwt")):
        return "auth"
    if "csrf" in lowered or "xsrf" in lowered:
        return "csrf"
    if any(word in lowered for word in ("analytics", "track", "_ga", "_gid")):
        return "tracking"
    if any(word in lowered for word in ("pref", "theme", "locale", "lang")):
        return "preference"
    return "unknown"


def _parse_set_cookie(value: str) -> dict[str, str | bool]:
    parts = [part.strip() for part in value.split(";")]
    first = parts[0].split("=", 1)
    result: dict[str, str | bool] = {
        "name": first[0],
        "value": first[1] if len(first) == 2 else "",
    }
    for part in parts[1:]:
        key, _, item_value = part.partition("=")
        result[key.lower()] = item_value if item_value else True
    return result


def analyze_cookies(path: Path) -> list[CookieReview]:
    """Extract request and response cookies and review response attributes."""
    _, entries = _load_har(path)
    results: list[CookieReview] = []
    for raw in entries:
        request, response = _request_response(raw)
        url = str(request.get("url", ""))
        for item in _items(request.get("cookies")):
            name = str(item.get("name", ""))
            results.append(
                CookieReview(
                    name=name,
                    source="request cookie",
                    source_url=redact_text(url),
                    cookie_type=_cookie_type(name),
                )
            )
        request_headers = _headers(request.get("headers"))
        raw_cookie = _header(request_headers, "cookie")
        for pair in raw_cookie.split(";") if raw_cookie else []:
            name = pair.partition("=")[0].strip()
            if name:
                results.append(
                    CookieReview(
                        name=name,
                        source="request Cookie header",
                        source_url=redact_text(url),
                        cookie_type=_cookie_type(name),
                    )
                )
        response_headers = _headers(response.get("headers"))
        set_cookie_values = [
            str(item.get("value", ""))
            for item in _items(response.get("headers"))
            if str(item.get("name", "")).lower() == "set-cookie"
        ]
        set_cookie_values.extend(
            f"{item.get('name', '')}={item.get('value', '')}"
            for item in _items(response.get("cookies"))
        )
        for value in set_cookie_values:
            parsed = _parse_set_cookie(value)
            name = str(parsed.get("name", ""))
            cookie_type = _cookie_type(name)
            secure = bool(parsed.get("secure", False))
            http_only = bool(parsed.get("httponly", False))
            same_site = str(parsed.get("samesite", ""))
            observations = []
            if not secure:
                observations.append("Secure attribute is missing (warning).")
            if cookie_type in {"session", "auth"} and not http_only:
                observations.append(
                    "HttpOnly is missing on a likely sensitive cookie (warning)."
                )
            elif not http_only:
                observations.append("HttpOnly attribute is missing (informational).")
            if not same_site:
                observations.append("SameSite attribute is missing (informational).")
            results.append(
                CookieReview(
                    name=name,
                    source="response Set-Cookie header",
                    source_url=redact_text(url),
                    cookie_type=cookie_type,
                    secure=secure,
                    http_only=http_only,
                    same_site=same_site,
                    domain=str(parsed.get("domain", "")),
                    path=str(parsed.get("path", "")),
                    expires=str(parsed.get("expires", "")),
                    max_age=str(parsed.get("max-age", "")),
                    observations=observations,
                )
            )
        _ = response_headers
    unique = {
        (item.name, item.source, item.source_url, item.same_site): item
        for item in results
    }
    return list(unique.values())


def analyze_headers(path: Path) -> list[HeaderReview]:
    """Review security-relevant response headers without declaring vulnerabilities."""
    _, entries = _load_har(path)
    reviews: list[HeaderReview] = []
    for raw in entries:
        request, response = _request_response(raw)
        url = redact_text(str(request.get("url", "")))
        headers = {
            key.lower(): value
            for key, value in _headers(response.get("headers")).items()
        }
        for name in SECURITY_HEADERS:
            if name in headers:
                value = redact_text(headers[name])
                classification = "informational"
                observation = (
                    "Header observed; validate its policy in application context."
                )
                if name == "access-control-allow-origin" and value == "*":
                    classification = "needs manual review"
                    observation = (
                        "Wildcard CORS origin observed; assess with credentials "
                        "and data sensitivity."
                    )
                reviews.append(
                    HeaderReview(
                        source_url=url,
                        header=name,
                        value=value,
                        classification=classification,
                        observation=observation,
                    )
                )
        for name in (
            "strict-transport-security",
            "content-security-policy",
            "x-content-type-options",
        ):
            if name not in headers:
                reviews.append(
                    HeaderReview(
                        source_url=url,
                        header=name,
                        value="<missing>",
                        classification="informational",
                        observation=(
                            "Header not observed in this response; applicability "
                            "requires manual review."
                        ),
                    )
                )
    return reviews


def _registrable_hint(host: str) -> str:
    parts = host.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def analyze_third_parties(
    path: Path, sensitive: list[SensitiveMaterial] | None = None
) -> list[ThirdPartyReview]:
    """Map hosts outside the primary capture host's approximate root domain."""
    summary = parse_har(path)
    if not summary.entries:
        return []
    primary_host = urlsplit(summary.entries[0].url).hostname or ""
    primary_root = _registrable_hint(primary_host)
    sensitive = sensitive if sensitive is not None else detect_sensitive_material(path)
    grouped: dict[str, dict[str, Any]] = {}
    for entry in summary.entries:
        host = urlsplit(entry.url).hostname or ""
        if not host or _registrable_hint(host) == primary_root:
            continue
        item = grouped.setdefault(
            host,
            {"count": 0, "methods": set(), "categories": set(), "urls": set()},
        )
        item["count"] += 1
        item["methods"].add(entry.method)
        item["urls"].add(redact_text(entry.url))
        item["categories"].update(
            finding.category
            for finding in sensitive
            if (urlsplit(finding.source_url).hostname or "") == host
        )
    return [
        ThirdPartyReview(
            host=host,
            request_count=item["count"],
            methods=sorted(item["methods"]),
            sensitive_categories=sorted(item["categories"]),
            source_urls=sorted(item["urls"]),
        )
        for host, item in sorted(grouped.items())
    ]


def analyze_cache(path: Path) -> list[CacheReview]:
    """Identify potentially sensitive responses whose caching needs manual review."""
    summary = parse_har(path)
    results: list[CacheReview] = []
    for entry in summary.entries:
        parsed = urlsplit(entry.url)
        sensitive_path = any(
            word in parsed.path.lower()
            for word in ("api", "account", "user", "profile", "session", "token")
        )
        sensitive_mime = "json" in entry.mime_type.lower()
        if not (sensitive_path or sensitive_mime):
            continue
        cache_control = _header(entry.response_headers, "cache-control")
        lowered = cache_control.lower()
        observation = ""
        if not cache_control:
            observation = (
                "No Cache-Control header observed on an API or "
                "sensitive-looking response."
            )
        elif "public" in lowered:
            observation = (
                "Cache-Control permits public caching of an API or "
                "sensitive-looking response."
            )
        else:
            match = re.search(r"max-age\s*=\s*(\d+)", lowered)
            if match and int(match.group(1)) >= 86400:
                observation = (
                    "A long cache max-age was observed on an API or "
                    "sensitive-looking response."
                )
        if observation:
            results.append(
                CacheReview(
                    source_url=redact_text(entry.url),
                    observation=observation,
                    cache_control=redact_text(cache_control or "<missing>"),
                )
            )
    return results


def _finding_id(category: str, location: str, asset: str) -> str:
    digest = sha256(f"{category}|{location}|{asset}".encode()).hexdigest()[:10]
    return f"HAR-{digest.upper()}"


def analyze_har(path: Path) -> HarAnalysis:
    """Run all passive analyzers and return a redacted, serializable result."""
    summary = parse_har(path)
    endpoints = extract_endpoints(path)
    sensitive = detect_sensitive_material(path)
    cookies = analyze_cookies(path)
    headers = analyze_headers(path)
    third_parties = analyze_third_parties(path, sensitive)
    cache_review = analyze_cache(path)
    primary_host = urlsplit(summary.entries[0].url).hostname if summary.entries else ""
    findings: list[Finding] = []
    for item in sensitive:
        findings.append(
            Finding(
                id=_finding_id(item.category, item.location, item.source_url),
                title=f"Sensitive material observed in {item.location}",
                type=item.category,
                severity="info",
                confidence="high",
                asset=item.source_url or primary_host or str(path),
                evidence="Sensitive value detected but intentionally not retained.",
                redacted_evidence=f"{item.name}: {item.redacted_value}",
                impact=(
                    "Captured HAR data may expose sensitive material if shared "
                    "or stored insecurely."
                ),
                recommendation=(
                    "Confirm necessity, rotate exposed test values when "
                    "appropriate, and share only redacted captures."
                ),
                source_module="har-analyzer",
                location=item.location,
            )
        )
    for item in cache_review:
        findings.append(
            Finding(
                id=_finding_id("cache-review", item.observation, item.source_url),
                title="Response caching needs manual review",
                type="risky-cache",
                severity="info",
                confidence="medium",
                asset=item.source_url,
                redacted_evidence=item.observation,
                impact=(
                    "Shared or long-lived caching may expose response data "
                    "depending on application context."
                ),
                recommendation=(
                    "Review response sensitivity and intended intermediary/"
                    "browser caching behavior."
                ),
                source_module="har-analyzer",
                location="response header",
            )
        )
    return HarAnalysis(
        source=str(path),
        primary_host=primary_host or "",
        summary=summary,
        endpoints=endpoints,
        sensitive_material=sensitive,
        cookies=cookies,
        headers=headers,
        third_parties=third_parties,
        cache_review=cache_review,
        findings=findings,
    )


def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "_None observed._"
    safe_rows = [
        [redact_text(str(cell)).replace("|", "\\|") for cell in row] for row in rows
    ]
    return "\n".join(
        [
            "| " + " | ".join(headers) + " |",
            "| " + " | ".join("---" for _ in headers) + " |",
            *["| " + " | ".join(row) + " |" for row in safe_rows],
        ]
    )


def render_markdown(analysis: HarAnalysis) -> str:
    """Render a redacted HAR analysis report."""
    endpoint_table = _md_table(
        [
            "Method",
            "Host",
            "Path",
            "Query names",
            "Statuses",
            "MIME types",
            "Count",
        ],
        [
            [
                item.method,
                item.host,
                item.path,
                ", ".join(item.query_parameters) or "—",
                ", ".join(map(str, item.status_codes)),
                ", ".join(item.mime_types),
                str(item.count),
            ]
            for item in analysis.endpoints
        ],
    )
    sensitive_rows = [
        [item.category, item.location, item.source_url, item.name, item.redacted_value]
        for item in analysis.sensitive_material
    ]
    cookie_rows = [
        [
            item.name,
            item.cookie_type,
            item.source,
            "yes" if item.secure else "no",
            "yes" if item.http_only else "no",
            item.same_site or "—",
            "; ".join(item.observations) or "No attribute warning.",
        ]
        for item in analysis.cookies
    ]
    header_rows = [
        [item.header, item.classification, item.value, item.observation]
        for item in analysis.headers
    ]
    third_party_rows = [
        [
            item.host,
            str(item.request_count),
            ", ".join(item.methods),
            ", ".join(item.sensitive_categories) or "none observed",
            ", ".join(item.source_urls),
        ]
        for item in analysis.third_parties
    ]
    cache_rows = [
        [item.source_url, item.classification, item.cache_control, item.observation]
        for item in analysis.cache_review
    ]
    sensitive_table = _md_table(
        ["Category", "Location", "Source URL", "Name", "Value"], sensitive_rows
    )
    cookie_table = _md_table(
        ["Name", "Type", "Source", "Secure", "HttpOnly", "SameSite", "Observations"],
        cookie_rows,
    )
    header_table = _md_table(
        ["Header", "Classification", "Value", "Observation"], header_rows
    )
    third_party_table = _md_table(
        ["Host", "Requests", "Methods", "Sensitive categories", "Source URLs"],
        third_party_rows,
    )
    cache_table = _md_table(
        ["Source URL", "Classification", "Cache-Control", "Observation"], cache_rows
    )
    return redact_text(
        f"""# BugBountyScout HAR Analysis

## Summary

- **Source:** `{analysis.source}`
- **Primary host:** `{analysis.primary_host or "not available"}`
- **Entries:** {analysis.summary.entry_count}
- **Normalized endpoints:** {len(analysis.endpoints)}
- **Sensitive-material observations:** {len(analysis.sensitive_material)}
- **Third-party hosts:** {len(analysis.third_parties)}

## Endpoint inventory

{endpoint_table}

## Sensitive material findings

{sensitive_table}

## Cookie review

{cookie_table}

## Header review

{header_table}

## Third-party leakage map

{third_party_table}

## Cache review

{cache_table}

## Manual follow-up checklist

- Confirm every captured asset was authorized and in scope.
- Validate observations in context; missing headers are not automatically
  vulnerabilities.
- Review whether sensitive values were necessary in each location.
- Confirm cookie and cache behavior in the browser without bypassing controls.
- Remove or redact the original HAR before sharing it.

## Redaction notice

Values matching token, JWT, API key, cookie, session, CSRF, OAuth, email,
phone-number, and secret-like patterns are redacted by default. Detection is
local only and does not validate secrets against provider APIs.
"""
    )


def render_json(analysis: HarAnalysis) -> str:
    """Serialize analysis after recursively redacting string output."""
    raw = analysis.model_dump(mode="json")

    def sanitize(value: Any) -> Any:
        if isinstance(value, str):
            return redact_text(value)
        if isinstance(value, list):
            return [sanitize(item) for item in value]
        if isinstance(value, dict):
            return {key: sanitize(item) for key, item in value.items()}
        return value

    return json.dumps(sanitize(raw), indent=2)
