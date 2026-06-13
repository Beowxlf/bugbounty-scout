"""Passive HAR metadata parsing."""

import json
from collections import Counter
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


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


def _headers(items: Any) -> dict[str, str]:
    if not isinstance(items, list):
        return {}
    return {
        str(item.get("name", "")): str(item.get("value", ""))
        for item in items
        if isinstance(item, dict) and item.get("name")
    }


def parse_har(path: Path) -> HarSummary:
    """Load a HAR file and extract non-secret-scanning metadata."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not parse HAR file {path}: {exc}") from exc
    raw_entries = data.get("log", {}).get("entries")
    if not isinstance(raw_entries, list):
        raise ValueError("HAR must contain a log.entries list")

    entries: list[HarEntry] = []
    for raw in raw_entries:
        if not isinstance(raw, dict):
            continue
        request = raw.get("request", {})
        response = raw.get("response", {})
        content = response.get("content", {})
        entries.append(
            HarEntry(
                method=str(request.get("method", "")),
                url=str(request.get("url", "")),
                status=int(response.get("status", 0)),
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
