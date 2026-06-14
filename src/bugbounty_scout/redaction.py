"""Deterministic, local sensitive-data redaction."""

import re

REPLACEMENTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"(?i)(authorization\s*:\s*bearer\s+)\S+"),
        r"\1<redacted-token>",
    ),
    (
        re.compile(r"(?i)(\bbearer\s+)\S+"),
        r"\1<redacted-token>",
    ),
    (
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"
            r"\.[A-Za-z0-9_-]{5,}\b"
        ),
        "<redacted-jwt>",
    ),
    (
        re.compile(r"(?im)^(\s*(?:set-)?cookie\s*:\s*).+$"),
        r"\1<redacted-cookie>",
    ),
    (
        re.compile(
            r"(?i)(\b(?:api[_-]?key|apikey|access[_-]?token|client[_-]?secret|"
            r"secret|password|passwd|session[_-]?id|sessionid)\b"
            r"\s*[=:]\s*[\"']?)([^\"'\s,;&}]+)"
        ),
        r"\1<redacted-secret>",
    ),
    (
        re.compile(
            r"(?i)(\b(?:csrf|xsrf|oauth[_-]?code|authorization[_-]?code|"
            r"refresh[_-]?token)\b\s*[=:]\s*[\"']?)([^\"'\s,;&}]+)"
        ),
        r"\1<redacted-secret>",
    ),
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "<redacted-private-key>",
    ),
    (
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "<redacted-email>",
    ),
    (
        re.compile(
            r"(?<!\w)(?:\+?1[-.\s]?)?"
            r"(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}(?!\w)"
        ),
        "<redacted-phone>",
    ),
)


def redact_text(text: str) -> str:
    """Return text with common sensitive values replaced."""
    redacted = text
    for pattern, replacement in REPLACEMENTS:
        redacted = pattern.sub(replacement, redacted)
    return redacted
