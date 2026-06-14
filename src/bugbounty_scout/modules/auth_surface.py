"""Passive, local-only authentication and session surface analysis."""

import base64
import json
import re
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from bugbounty_scout.models import (
    AuthSurfaceInventory,
    CacheObservation,
    Confidence,
    CookieObservation,
    CorsObservation,
    Endpoint,
    EndpointSource,
    JwtObservation,
    SecurityHeaderObservation,
    Severity,
)
from bugbounty_scout.redaction import redact_text

SUPPORTED = {".har", ".json", ".txt", ".http", ".yml", ".yaml"}
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]+\b")
AUTH_TAGS = {
    "password-reset": (
        "password/reset",
        "reset-password",
        "password-reset",
        "forgot-password",
    ),
    "password-change": ("password/change", "change-password", "password-change"),
    "magic-link": ("magic-link", "magic_link"),
    "verify-email": ("verify-email", "verify_email"),
    "login": ("login", "signin", "sign-in"),
    "logout": ("logout", "signout", "sign-out"),
    "register": ("register",),
    "signup": ("signup", "sign-up"),
    "mfa": ("mfa", "2fa"),
    "otp": ("otp",),
    "oauth": ("oauth",),
    "callback": ("callback",),
    "token": ("token",),
    "refresh": ("refresh",),
    "session": ("session",),
    "invite": ("invite",),
    "csrf": ("csrf", "xsrf"),
    "sso": ("sso",),
    "saml": ("saml",),
    "oidc": ("oidc",),
}
SECURITY_HEADERS = {
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "x-content-type-options",
    "cache-control",
    "pragma",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
}
STANDARD_CLAIMS = {
    "alg",
    "typ",
    "kid",
    "iss",
    "sub",
    "aud",
    "exp",
    "nbf",
    "iat",
    "jti",
    "scope",
    "scp",
    "roles",
    "role",
    "permissions",
    "tenant",
    "tenantId",
    "org",
    "orgId",
    "email",
    "username",
    "name",
}


def _id(prefix: str, value: str) -> str:
    return f"{prefix}-{sha256(value.encode()).hexdigest()[:12]}"


def _dt(value: Any) -> datetime | None:
    try:
        return datetime.fromtimestamp(int(value), UTC)
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def _list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [v for v in re.split(r"[ ,]+", str(value)) if v]


def decode_jwt(
    token: str, source_file: str = "", location: str = "text"
) -> JwtObservation | None:
    """Decode JWT metadata without signature verification or network access."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        def decode(part: str) -> Any:
            return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))

        header, payload = decode(parts[0]), decode(parts[1])
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return None
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    iat, exp, nbf = (
        _dt(payload.get("iat")),
        _dt(payload.get("exp")),
        _dt(payload.get("nbf")),
    )
    risks = []
    if not exp:
        risks.append("missing-exp")
    lifetime = int((exp - iat).total_seconds()) if exp and iat else None
    if lifetime and lifetime > 86400:
        risks.append("long-lifetime")
    now = datetime.now(UTC)
    if exp and exp < now:
        risks.append("expired")
    if exp and (exp - now).days > 365:
        risks.append("far-future-expiry")
    roles = _list(payload.get("roles", payload.get("role")))
    if any(re.search(r"admin|owner|superuser", role, re.I) for role in roles):
        risks.append("admin-like-role")
    sensitive = [key for key in ("email", "username", "name") if key in payload]
    if sensitive:
        risks.append("sensitive-claims")
    if not payload.get("aud"):
        risks.append("missing-audience")
    if not payload.get("iss"):
        risks.append("missing-issuer")
    if "url" in location.lower() or "query" in location.lower():
        risks.append("token-in-url")
    alg = str(header.get("alg", ""))
    if alg.lower() in {"none", "hs256", "hs384", "hs512"}:
        risks.append("unusual-algorithm-manual-review")
    tenant = [key for key in ("tenant", "tenantId") if key in payload]
    org = [key for key in ("org", "orgId") if key in payload]
    if tenant:
        risks.append("tenant-claims")
    if org:
        risks.append("org-claims")
    severity = (
        Severity.MEDIUM
        if "token-in-url" in risks
        else Severity.LOW
        if risks
        else Severity.INFO
    )
    return JwtObservation(
        id=_id("jwt", token),
        token_fingerprint=sha256(token.encode()).hexdigest()[:16],
        source_type=Path(source_file).suffix.lstrip(".") or "text",
        source_file=source_file,
        location=location,
        algorithm=alg,
        token_type=str(header.get("typ", "")),
        key_id=str(header.get("kid", "")),
        issuer=str(payload.get("iss", "")),
        subject_present="sub" in payload,
        audience=_list(payload.get("aud")),
        issued_at=iat,
        not_before=nbf,
        expires_at=exp,
        lifetime_seconds=lifetime,
        scopes=sorted(set(_list(payload.get("scope")) + _list(payload.get("scp")))),
        roles=roles,
        permissions=_list(payload.get("permissions")),
        tenant_claims=tenant,
        org_claims=org,
        sensitive_claims=sensitive,
        custom_claim_keys=sorted(set(payload) - STANDARD_CLAIMS),
        risk_tags=risks,
        severity=severity,
        confidence=Confidence.HIGH,
        evidence="",
        redacted_evidence=f"<redacted-jwt:{sha256(token.encode()).hexdigest()[:12]}>",
    )


def _cookie(
    name: str, raw: str, source: str, location: str, response: bool
) -> CookieObservation:
    parts = [p.strip() for p in raw.split(";")]
    attrs: dict[str, str] = {}
    flags = set()
    for part in parts[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            attrs[k.lower()] = v
        else:
            flags.add(part.lower())
    lower = name.lower()
    ctype = (
        "csrf"
        if "csrf" in lower or "xsrf" in lower
        else "session"
        if "sess" in lower
        else "auth"
        if any(x in lower for x in ("auth", "token", "jwt"))
        else "tracking"
        if any(x in lower for x in ("ga", "track"))
        else "preference"
        if any(x in lower for x in ("theme", "pref"))
        else "unknown"
    )
    secure, httponly, same = (
        "secure" in flags,
        "httponly" in flags,
        attrs.get("samesite", ""),
    )
    risks = []
    sensitive = ctype in {"session", "auth"}
    if response and sensitive and not secure:
        risks.append("missing-secure")
    if response and sensitive and not httponly:
        risks.append("missing-httponly")
    if response and sensitive and not same:
        risks.append("missing-samesite")
    domain = attrs.get("domain", "")
    if domain.startswith("."):
        risks.append("broad-domain")
    prefix = (
        "__Host-"
        if name.startswith("__Host-")
        else "__Secure-"
        if name.startswith("__Secure-")
        else ""
    )
    if prefix == "__Host-" and (not secure or domain or attrs.get("path") != "/"):
        risks.append("host-prefix-misuse")
    if prefix == "__Secure-" and not secure:
        risks.append("secure-prefix-misuse")
    if ctype == "csrf":
        risks.append("csrf-cookie-indicator")
    if not response and sensitive:
        risks.append("sensitive-request-cookie")
    try:
        max_age = int(attrs["max-age"]) if "max-age" in attrs else None
    except ValueError:
        max_age = None
    return CookieObservation(
        id=_id("cookie", source + location + name + raw),
        name=name,
        source_type=Path(source).suffix.lstrip("."),
        source_file=source,
        location=location,
        cookie_type=ctype,
        domain=domain,
        path=attrs.get("path", ""),
        secure=secure if response else None,
        httponly=httponly if response else None,
        samesite=same,
        expires=attrs.get("expires", ""),
        max_age=max_age,
        prefix=prefix,
        risk_tags=risks,
        severity=Severity.LOW if risks else Severity.INFO,
        evidence="",
        redacted_evidence=f"{name}=<redacted-cookie-value>",
    )


def _headers(items: Any) -> dict[str, str]:
    if isinstance(items, dict):
        return {str(k).lower(): str(v) for k, v in items.items()}
    return {
        str(i.get("name", "")).lower(): str(i.get("value", ""))
        for i in items or []
        if isinstance(i, dict)
    }


def _analyze_exchange(
    inv: AuthSurfaceInventory,
    request: dict[str, Any],
    response: dict[str, Any],
    source: str,
    index: int,
) -> None:
    url, status = str(request.get("url", "")), response.get("status")
    reqh, resh = (
        _headers(request.get("headers", [])),
        _headers(response.get("headers", [])),
    )
    texts = [
        (url, "request URL"),
        (json.dumps(request, default=str), "HAR request"),
        (json.dumps(response, default=str), "HAR response"),
    ]
    for text, location in texts:
        for token in JWT_RE.findall(text):
            obs = decode_jwt(token, source, location)
            if obs and obs.id not in {x.id for x in inv.jwt_observations}:
                inv.jwt_observations.append(obs)
    for raw, response_cookie, location in (
        (reqh.get("cookie", ""), False, "request Cookie header"),
        (resh.get("set-cookie", ""), True, "response Set-Cookie header"),
    ):
        if raw:
            chunks = [raw] if response_cookie else raw.split(";")
            for chunk in chunks:
                if "=" in chunk:
                    name = chunk.strip().split("=", 1)[0]
                    inv.cookie_observations.append(
                        _cookie(name, chunk, source, location, response_cookie)
                    )
    for item in request.get("cookies", []):
        if isinstance(item, dict) and item.get("name"):
            inv.cookie_observations.append(
                _cookie(
                    str(item["name"]),
                    f"{item['name']}={item.get('value', '')}",
                    source,
                    "HAR request cookie",
                    False,
                )
            )
    for item in response.get("cookies", []):
        if isinstance(item, dict) and item.get("name"):
            raw = f"{item['name']}={item.get('value', '')}; Path={item.get('path', '')}"
            for flag, key in (("Secure", "secure"), ("HttpOnly", "httpOnly")):
                if item.get(key):
                    raw += f"; {flag}"
            if item.get("sameSite"):
                raw += f"; SameSite={item['sameSite']}"
            inv.cookie_observations.append(
                _cookie(str(item["name"]), raw, source, "HAR response cookie", True)
            )
    for name, value in resh.items():
        if name in SECURITY_HEADERS:
            risks = []
            if name == "content-security-policy":
                low = value.lower()
                for pattern, tag in (
                    ("'unsafe-inline'", "csp-unsafe-inline"),
                    ("'unsafe-eval'", "csp-unsafe-eval"),
                    ("*", "csp-wildcard"),
                ):
                    if pattern in low:
                        risks.append(tag)
                if "object-src" not in low:
                    risks.append("csp-missing-object-src")
                if "frame-ancestors" not in low:
                    risks.append("csp-missing-frame-ancestors")
            inv.security_header_observations.append(
                SecurityHeaderObservation(
                    id=_id("header", source + str(index) + name + value),
                    header_name=name,
                    value_summary=redact_text(value)[:300],
                    source_type="har",
                    source_file=source,
                    url=url,
                    status_code=status,
                    risk_tags=risks,
                    severity=Severity.LOW if risks else Severity.INFO,
                    redacted_evidence=f"{name}: {redact_text(value)}",
                    recommendation="Manually review header policy in application context.",
                )
            )
    if "access-control-allow-origin" in resh:
        origin, risks = resh.get("access-control-allow-origin", ""), []
        creds = resh.get("access-control-allow-credentials", "").lower() == "true"
        if origin == "*":
            risks.append("wildcard-origin")
        if origin == "null":
            risks.append("null-origin")
        if creds:
            risks.append("credentials-allowed")
        if origin == "*" and creds:
            risks.append("wildcard-with-credentials")
        request_origin = reqh.get("origin", "")
        if request_origin and origin == request_origin:
            risks.append("reflected-looking-origin")
        if (
            request_origin
            and origin == request_origin
            and "origin" not in resh.get("vary", "").lower()
        ):
            risks.append("missing-vary-origin")
        methods = _list(resh.get("access-control-allow-methods", ""))
        if "*" in methods or len(methods) > 5:
            risks.append("broad-methods")
        inv.cors_observations.append(
            CorsObservation(
                id=_id("cors", source + str(index) + origin),
                source_type="har",
                source_file=source,
                url=url,
                allow_origin=origin,
                allow_credentials=creds,
                allow_methods=methods,
                allow_headers=_list(resh.get("access-control-allow-headers", "")),
                expose_headers=_list(resh.get("access-control-expose-headers", "")),
                vary=resh.get("vary", ""),
                risk_tags=risks,
                severity=Severity.LOW if risks else Severity.INFO,
                redacted_evidence="Observed CORS response headers (values contain no credentials).",
                recommendation="Validate browser and credential context manually; observation alone does not establish exploitability.",
            )
        )
    body = str(response.get("content", {}).get("text", ""))
    sensitive = bool(
        re.search(
            r"(?i)email|phone|account|profile|token|session|password|tenant|invoice",
            url + body,
        )
    )
    cache = resh.get("cache-control", "")
    risks = []
    if sensitive and not cache:
        risks.append("sensitive-response-missing-cache-control")
    if sensitive and "public" in cache.lower():
        risks.append("sensitive-response-public-cache")
    match = re.search(r"max-age=(\d+)", cache, re.I)
    if sensitive and match and int(match.group(1)) > 3600:
        risks.append("sensitive-response-long-max-age")
    if risks:
        inv.cache_observations.append(
            CacheObservation(
                id=_id("cache", source + str(index) + url),
                source_type="har",
                source_file=source,
                url=url,
                status_code=status,
                cache_control=cache,
                pragma=resh.get("pragma", ""),
                expires=resh.get("expires", ""),
                content_type=str(
                    response.get("content", {}).get(
                        "mimeType", resh.get("content-type", "")
                    )
                ),
                sensitive_context=sensitive,
                risk_tags=risks,
                severity=Severity.LOW,
                redacted_evidence="Sensitive-looking response context with observed cache metadata.",
                recommendation="Confirm whether shared or browser caching can expose authenticated data.",
            )
        )
    _add_endpoint(inv, url, str(request.get("method", "UNKNOWN")), source)


def _add_endpoint(
    inv: AuthSurfaceInventory, url: str, method: str, source: str
) -> None:
    low = url.lower()
    tags = sorted(
        tag for tag, needles in AUTH_TAGS.items() if any(n in low for n in needles)
    )
    if not tags:
        return
    parsed = urlsplit(url)
    path = parsed.path or url
    eid = _id("auth-endpoint", method + path)
    if eid not in {e.id for e in inv.auth_endpoints}:
        inv.auth_endpoints.append(
            Endpoint(
                id=eid,
                method=method,
                scheme=parsed.scheme,
                host=parsed.netloc,
                path=path,
                normalized_path=path,
                url=url,
                source=[EndpointSource(type="auth-surface", file=source, url=url)],
                source_file=source,
                source_module="auth-surface-analyzer",
                risk_tags=tags,
                auth_indicators=tags,
            )
        )


def _load(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".har", ".json"}:
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in {path}: {exc.msg}") from exc
    if path.suffix.lower() in {".yml", ".yaml"}:
        try:
            return yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML in {path}") from exc
    return text


def scan_file(path: Path) -> AuthSurfaceInventory:
    if not path.is_file():
        raise ValueError(f"Input file not found: {path}")
    if path.suffix.lower() not in SUPPORTED:
        raise ValueError(f"Unsupported file type: {path.suffix}")
    data = _load(path)
    inv = AuthSurfaceInventory(source_files=[str(path)])
    if path.suffix.lower() == ".har":
        entries = data.get("log", {}).get("entries") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            raise ValueError("Invalid HAR: expected log.entries list")
        for i, entry in enumerate(entries):
            _analyze_exchange(
                inv, entry.get("request", {}), entry.get("response", {}), str(path), i
            )
    else:
        text = data if isinstance(data, str) else json.dumps(data, default=str)
        for token in JWT_RE.findall(text):
            obs = decode_jwt(token, str(path), "local file")
            if obs:
                inv.jwt_observations.append(obs)
        # Raw HTTP header blocks.
        req, resp = {}, {}
        lines = text.splitlines()
        first = lines[0] if lines else ""
        target = resp if first.startswith("HTTP/") else req
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                target.setdefault("headers", []).append(
                    {"name": k.strip(), "value": v.strip()}
                )
        if req or resp:
            _analyze_exchange(inv, req, resp, str(path), 0)
        if isinstance(data, dict):
            for endpoint in data.get("endpoints", data.get("routes", [])):
                if isinstance(endpoint, dict):
                    _add_endpoint(
                        inv,
                        str(endpoint.get("url") or endpoint.get("path", "")),
                        str(endpoint.get("method", "UNKNOWN")),
                        str(path),
                    )
        for match in re.finditer(r"https?://[^\s\"'<>]+|/[A-Za-z0-9_./-]+", text):
            _add_endpoint(inv, match.group(), "UNKNOWN", str(path))
    return _finalize(inv)


def scan_folder(folder: Path) -> AuthSurfaceInventory:
    if not folder.is_dir():
        raise ValueError(f"Folder not found: {folder}")
    merged = AuthSurfaceInventory()
    for path in sorted(
        p for p in folder.rglob("*") if p.is_file() and p.suffix.lower() in SUPPORTED
    ):
        _merge(merged, scan_file(path))
    return _finalize(merged)


def _merge(target: AuthSurfaceInventory, source: AuthSurfaceInventory) -> None:
    for field in (
        "jwt_observations",
        "cookie_observations",
        "security_header_observations",
        "cors_observations",
        "cache_observations",
        "auth_endpoints",
    ):
        existing = {x.id for x in getattr(target, field)}
        getattr(target, field).extend(
            x for x in getattr(source, field) if x.id not in existing
        )
    target.source_files.extend(
        x for x in source.source_files if x not in target.source_files
    )


def _finalize(inv: AuthSurfaceInventory) -> AuthSurfaceInventory:
    tags = {tag for endpoint in inv.auth_endpoints for tag in endpoint.risk_tags}
    leads = [
        "Are session cookies rotated after login and privilege changes?",
        "Are authentication errors generic enough to avoid account enumeration?",
    ]
    mapping = {
        "password-reset": "Are password reset tokens single-use, scoped, and short-lived?",
        "logout": "Are logout actions CSRF-protected where applicable and do they invalidate sessions?",
        "refresh": "Are refresh tokens protected from client-side exposure and rotated safely?",
        "oauth": "Are OAuth/OIDC callback and redirect URLs strictly validated?",
        "callback": "Are callback URLs strictly allowlisted and bound to the initiating flow?",
        "invite": "Are invite or magic-link flows scoped to the correct user, organization, and tenant?",
        "magic-link": "Are magic links single-use and short-lived?",
        "mfa": "Are MFA and OTP attempts rate limited without enabling enumeration?",
        "otp": "Are MFA and OTP attempts rate limited without enabling enumeration?",
    }
    leads.extend(question for tag, question in mapping.items() if tag in tags)
    if any(c.cookie_type == "csrf" for c in inv.cookie_observations):
        leads.append(
            "Is the CSRF token bound to the authenticated session and validated on state changes?"
        )
    inv.session_review_leads = list(dict.fromkeys(leads))
    inv.summary = {
        "sources_analyzed": len(inv.source_files),
        "jwt_observations": len(inv.jwt_observations),
        "cookie_observations": len(inv.cookie_observations),
        "security_header_observations": len(inv.security_header_observations),
        "cors_observations": len(inv.cors_observations),
        "cache_observations": len(inv.cache_observations),
        "auth_endpoints": len(inv.auth_endpoints),
        "mode": "passive-local-only",
    }
    return inv


def load_or_scan(path: Path) -> AuthSurfaceInventory:
    if path.is_dir():
        return scan_folder(path)
    if path.suffix.lower() == ".json":
        data = _load(path)
        if isinstance(data, dict) and "jwt_observations" in data:
            return AuthSurfaceInventory.model_validate(data)
    return scan_file(path)


def checklist(inventory: AuthSurfaceInventory) -> dict[str, list[str]]:
    return {
        "JWT review": [
            "Confirm token lifetime, issuer, audience, scope, and role semantics manually.",
            *[
                f"Review {tag.replace('-', ' ')} signal for token {j.token_fingerprint}."
                for j in inventory.jwt_observations
                for tag in j.risk_tags
            ],
        ],
        "Session cookie review": [
            "Confirm session identifiers use appropriate Secure, HttpOnly, SameSite, Path, Domain, rotation, and expiry controls."
        ],
        "CSRF review": [
            "Confirm state-changing authenticated actions use an appropriate CSRF defense for their browser context."
        ],
        "Password reset review": [
            q for q in inventory.session_review_leads if "password reset" in q.lower()
        ]
        or [
            "Confirm reset tokens are single-use, scoped, unpredictable, and short-lived."
        ],
        "OAuth/OIDC/SAML review": [
            "Confirm redirect/callback allowlists, state/nonce handling, account linking, and tenant binding manually."
        ],
        "CORS review": [
            "Validate observed origins, credentials, Vary behavior, methods, headers, and browser context manually."
        ],
        "Cache review": [
            "Confirm authenticated or PII-bearing responses cannot be stored by inappropriate shared caches."
        ],
        "Header hardening review": [
            "Assess observed security headers in application context; absence alone is not a vulnerability."
        ],
        "Tenant/org auth review": [
            "Confirm tokens and auth flows enforce server-side organization and tenant boundaries."
        ],
    }


def render_json(inventory: AuthSurfaceInventory) -> str:
    safe = inventory.model_copy(deep=True)
    for item in (
        safe.jwt_observations
        + safe.cookie_observations
        + safe.security_header_observations
        + safe.cors_observations
        + safe.cache_observations
    ):
        item.evidence = ""
    return json.dumps(safe.model_dump(mode="json"), indent=2, sort_keys=True)


def render_checklist(inventory: AuthSurfaceInventory, format: str = "markdown") -> str:
    data = checklist(inventory)
    if format == "json":
        return json.dumps(data, indent=2)
    return (
        "# Auth Surface Manual Checklist\n\n"
        + "\n\n".join(
            f"## {section}\n" + "\n".join(f"- [ ] {q}" for q in questions)
            for section, questions in data.items()
        )
        + "\n"
    )


def render_markdown(inv: AuthSurfaceInventory) -> str:
    def rows(items: list[Any], label: str) -> str:
        if not items:
            return "_No observations._"
        return "\n".join(
            f"- **{getattr(x, 'name', getattr(x, 'header_name', getattr(x, 'url', getattr(x, 'token_fingerprint', label))))}** — {', '.join(x.risk_tags) or 'informational'}"
            for x in items
        )

    endpoint_rows = (
        "\n".join(
            f"- `{e.method} {e.path}` — {', '.join(e.risk_tags)}"
            for e in inv.auth_endpoints
        )
        or "_No auth endpoints observed._"
    )
    high = [
        f"{type(x).__name__}: {', '.join(x.risk_tags)}"
        for group in (
            inv.jwt_observations,
            inv.cookie_observations,
            inv.cors_observations,
            inv.cache_observations,
        )
        for x in group
        if x.risk_tags
    ]
    return f"""# Auth Surface Analyzer Report

## Summary
Passive local analysis only. Sources: {len(inv.source_files)}; JWTs: {len(inv.jwt_observations)}; cookies: {len(inv.cookie_observations)}.

## Sources analyzed
{chr(10).join(f"- `{redact_text(x)}`" for x in inv.source_files) or "_None._"}

## JWT observations
{rows(inv.jwt_observations, "JWT")}

## Cookie observations
{rows(inv.cookie_observations, "cookie")}

## Security header observations
{rows(inv.security_header_observations, "header")}

## CORS observations
{rows(inv.cors_observations, "CORS")}

## Cache observations
{rows(inv.cache_observations, "cache")}

## Auth/session endpoint review leads
{endpoint_rows}

## High-interest manual review items
{chr(10).join(f"- {x}" for x in high) or "_None._"}

## Manual checklist
{chr(10).join(f"- [ ] {q}" for q in inv.session_review_leads)}

## Redaction notice
Tokens, cookie values, authorization material, secrets, and PII are redacted; JWT exports contain fingerprints and claim summaries only.

## Limitations
Observations are heuristic and do not prove exploitability. No requests, replay, signature validation, brute force, payload generation, fuzzing, JWKS access, or active CORS testing are performed.
"""
