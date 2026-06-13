"""Offline scope policy checks."""

from fnmatch import fnmatchcase
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import ValidationError

from bugbounty_scout.config import load_data
from bugbounty_scout.models import ScopeDecision, ScopeProfile


def load_scope(path: Path) -> ScopeProfile:
    """Load and validate a scope profile."""
    try:
        return ScopeProfile.model_validate(load_data(path))
    except ValidationError as exc:
        raise ValueError(f"Invalid scope profile: {exc}") from exc


def _parse_target(url: str) -> tuple[str, str, str] | None:
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    host = parsed.hostname.rstrip(".").lower()
    path = parsed.path or "/"
    return host, path, f"{host}{path}"


def _match_rule(rule: str, host: str, path: str, host_path: str) -> bool:
    normalized = rule.strip().lower().rstrip(".")
    if not normalized:
        return False
    if "://" in normalized:
        parsed = urlsplit(normalized)
        if not parsed.hostname:
            return False
        rule_host = parsed.hostname.rstrip(".")
        rule_path = parsed.path or "/"
        return _match_host(rule_host, host) and fnmatchcase(path, rule_path)
    if normalized.startswith("/"):
        return fnmatchcase(path, normalized)
    if "/" in normalized:
        return fnmatchcase(host_path, normalized)
    return _match_host(normalized, host)


def _match_host(rule: str, host: str) -> bool:
    if rule.startswith("*."):
        suffix = rule[2:]
        return host.endswith(f".{suffix}") and host != suffix
    return host == rule


def check_scope(url: str, profile: ScopeProfile) -> ScopeDecision:
    """Evaluate a URL locally, with explicit exclusions taking precedence."""
    target = _parse_target(url)
    if target is None:
        return ScopeDecision(
            url=url,
            allowed=False,
            reason="Invalid URL; an explicit http:// or https:// URL is required.",
        )
    host, path, host_path = target

    for rule in profile.out_of_scope:
        if _match_rule(rule, host, path, host_path):
            return ScopeDecision(
                url=url,
                allowed=False,
                reason="Target matches an explicit out-of-scope rule.",
                matched_rule=rule,
            )
    for rule in profile.in_scope:
        if _match_rule(rule, host, path, host_path):
            return ScopeDecision(
                url=url,
                allowed=True,
                reason="Target matches an in-scope rule.",
                matched_rule=rule,
            )
    return ScopeDecision(
        url=url,
        allowed=False,
        reason="Target does not match any in-scope rule.",
    )


def scope_template() -> dict[str, object]:
    """Return a deliberately non-live scope template."""
    return {
        "program_name": "Replace with program name",
        "platform": "Replace with platform",
        "in_scope": ["example.test", "*.api.example.test"],
        "out_of_scope": ["admin.example.test", "example.test/private/*"],
        "forbidden_tests": ["denial of service", "social engineering"],
        "rate_limits": {"requests_per_second": 1},
        "auth_notes": "Use only authorized test accounts.",
        "report_notes": "Redact sensitive data before reporting.",
    }
