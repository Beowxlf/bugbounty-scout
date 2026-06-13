"""Passive frontend exposure analysis for local files and folders."""

import json
import re
from hashlib import sha256
from pathlib import Path

from bugbounty_scout.models import (
    ClientStorageReference,
    DomReviewLead,
    FrontendFinding,
    FrontendInventory,
    PostMessageLead,
)
from bugbounty_scout.modules.endpoints import extract_text_content
from bugbounty_scout.modules.sourcemaps import parse_source_map, references
from bugbounty_scout.redaction import redact_text

SUPPORTED_SUFFIXES = {".js", ".html", ".htm", ".json", ".txt", ".map"}
SECRET_PATTERNS = (
    (
        "jwt",
        "confirmed secret format",
        re.compile(r"\beyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]{5,}\b"),
    ),
    ("bearer-token", "likely secret", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._-]{8,}")),
    (
        "private-key",
        "confirmed secret format",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ),
    ("cloud-key", "confirmed secret format", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "stripe-publishable-key",
        "public identifier",
        re.compile(r"\bpk_(?:test|live)_[A-Za-z0-9]{8,}\b"),
    ),
    (
        "sentry-dsn",
        "public identifier",
        re.compile(r"https://[A-Za-z0-9]+@[^/\s]+/\d+"),
    ),
    (
        "analytics-id",
        "public identifier",
        re.compile(r"\b(?:UA-\d+-\d+|G-[A-Z0-9]{6,})\b"),
    ),
    (
        "oauth-client-id",
        "public identifier",
        re.compile(r"\b\d+-[a-z0-9]+\.apps\.googleusercontent\.com\b"),
    ),
    (
        "api-key",
        "potentially sensitive",
        re.compile(
            r"(?i)[\"']?(?:api[_-]?key|apikey|client[_-]?secret|"
            r"access[_-]?token|session[_-]?(?:id|token)?)[\"']?"
            r"\s*[:=]\s*[\"']?([^\"'\s,;}]{8,})"
        ),
    ),
)
RUNTIME_RE = re.compile(
    r"(?i)(__NEXT_DATA__|window\.(?:__INITIAL_STATE__|__APP_CONFIG__|"
    r"__RUNTIME_CONFIG__|__NUXT__)|import\.meta\.env|process\.env|"
    r"__webpack_public_path__|(?:runtime_)?config\s*[:=])"
)
CONFIG_RE = re.compile(
    r"(?i)\b(environment|env|debug|feature[_-]?\w+)\s*[:=]\s*([^,;\n}]+)"
)
INTERNAL_RE = re.compile(
    r"(?i)(https?://[^\s\"']*(?:internal|staging|dev|local)[^\s\"']*|\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+)"
)
STORAGE_RE = re.compile(
    r"(?i)(localStorage|sessionStorage|indexedDB|document\.cookie|caches)(?:\.(?:getItem|setItem|removeItem))?\s*\(?\s*[\"']?([A-Za-z0-9_.-]*)"
)
SENSITIVE_KEY_RE = re.compile(
    r"(?i)(token|jwt|session|password|secret|email|user|role|permission|tenant|org|account)"
)
SOURCES = (
    "location.href",
    "location.hash",
    "location.search",
    "document.URL",
    "document.referrer",
    "event.data",
    "localStorage",
    "sessionStorage",
    "document.cookie",
)
SINKS = (
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write",
    "eval(",
    "Function(",
    "setTimeout(",
    "setInterval(",
)


def _finding(
    path: Path,
    kind: str,
    evidence: str,
    line: int,
    classification: str = "needs manual validation",
    severity: str = "low",
) -> FrontendFinding:
    key = f"{path}:{kind}:{line}:{evidence}"
    return FrontendFinding(
        id=f"fe-{sha256(key.encode()).hexdigest()[:12]}",
        title=kind.replace("-", " ").title(),
        type=kind,
        severity=severity,
        confidence="high" if classification == "confirmed secret format" else "medium",
        asset=str(path),
        source_file=str(path),
        line=line,
        evidence="",
        redacted_evidence=redact_text(evidence.strip()),
        context={"classification": classification},
        risk_tags=[classification],
        recommendation=(
            "Manually validate necessity and exposure without contacting provider APIs."
        ),
    )


def _line(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def _analyze_text(path: Path, text: str, inventory: FrontendInventory) -> None:
    for kind, classification, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            item = _finding(
                path,
                kind,
                match.group(0),
                _line(text, match.start()),
                classification,
                "info" if classification == "public identifier" else "medium",
            )
            inventory.secrets.append(item)
            inventory.findings.append(item)
    for match in INTERNAL_RE.finditer(text):
        item = _finding(
            path,
            "internal-reference",
            match.group(0),
            _line(text, match.start()),
            "potentially sensitive",
        )
        inventory.findings.append(item)
    for match in RUNTIME_RE.finditer(text):
        nearby = text[match.start() : match.start() + 300].splitlines()[0]
        item = _finding(
            path,
            "runtime-config",
            nearby,
            _line(text, match.start()),
            "needs manual validation",
            "info",
        )
        item.context["config_keys"] = sorted(
            {m.group(1) for m in CONFIG_RE.finditer(nearby)}
        )
        inventory.runtime_configs.append(item)
        inventory.findings.append(item)
    inventory.source_maps.extend(references(path, text))
    extracted_endpoints = extract_text_content(path, text)
    inventory.routes.extend(extracted_endpoints)
    for endpoint in extracted_endpoints:
        if endpoint.host or endpoint.risk_tags:
            inventory.api_clients.append(
                _finding(
                    path,
                    "api-client-hint",
                    endpoint.url,
                    endpoint.source[0].line or 1,
                    "needs manual validation",
                    "info",
                )
            )
    lines = text.splitlines()
    for number, content in enumerate(lines, 1):
        for match in STORAGE_RE.finditer(content):
            key = match.group(2)
            inventory.storage_references.append(
                ClientStorageReference(
                    storage_type=match.group(1),
                    key=key,
                    source_file=str(path),
                    line=number,
                    risk="sensitive key manual review"
                    if SENSITIVE_KEY_RE.search(key)
                    else "manual review",
                    evidence="",
                    redacted_evidence=redact_text(content.strip()),
                )
            )
    for index, content in enumerate(lines):
        window = "\n".join(lines[max(0, index - 3) : min(len(lines), index + 4)])
        sources = [value for value in SOURCES if value in window]
        sinks = [value for value in SINKS if value in window]
        if sources and sinks and any(sink in content for sink in sinks):
            inventory.dom_review_leads.append(
                DomReviewLead(
                    source_file=str(path),
                    line=index + 1,
                    source_pattern=", ".join(sources),
                    sink_pattern=", ".join(sinks),
                    evidence="",
                    redacted_evidence=redact_text(window),
                    review_reason=(
                        "A client-controlled source appears near a dynamic DOM/code "
                        "sink; manually trace data flow."
                    ),
                )
            )
    message_markers = (
        'addEventListener("message"',
        "addEventListener('message'",
        ".onmessage",
        "postMessage(",
    )
    for index, content in enumerate(lines):
        if any(marker in content for marker in message_markers):
            window = "\n".join(lines[index : min(len(lines), index + 12)])
            has_origin = bool(re.search(r"event\.origin|\.origin\s*[!=]==?", window))
            reasons = []
            if not has_origin and ("message" in content or "onmessage" in content):
                reasons.append("no visible origin check")
            if re.search(r"postMessage\s*\([^,\n]+,\s*[\"']\*[\"']", window):
                reasons.append("wildcard target origin")
            if "event.data" in window and not re.search(
                r"(typeof|validate|schema|parse)", window, re.I
            ):
                reasons.append("event.data has no obvious validation")
            inventory.postmessage_leads.append(
                PostMessageLead(
                    source_file=str(path),
                    line=index + 1,
                    pattern=content.strip(),
                    has_origin_check=has_origin,
                    evidence="",
                    redacted_evidence=redact_text(window),
                    review_reason="; ".join(reasons)
                    or "Message handling or sending warrants manual review.",
                )
            )


def scan_file(path: Path) -> FrontendInventory:
    if not path.is_file():
        raise ValueError(f"Input file does not exist: {path}")
    if path.suffix.lower() not in SUPPORTED_SUFFIXES:
        raise ValueError(f"Unsupported input type: {path.suffix or '<none>'}")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Could not read input file {path}: {exc}") from exc
    inventory = FrontendInventory(source_files=[str(path)])
    if path.suffix.lower() == ".map":
        findings, embedded = parse_source_map(path)
        inventory.source_maps.extend(findings)
        for source, content in embedded:
            _analyze_text(Path(source), content, inventory)
    elif text.strip():
        _analyze_text(path, text, inventory)
        if path.suffix.lower() == ".json":
            try:
                json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON file {path}: {exc}") from exc
    return _finish(inventory)


def _finish(inventory: FrontendInventory) -> FrontendInventory:
    inventory.summary = {
        "files_analyzed": len(inventory.source_files),
        "findings": len(inventory.findings),
        "secrets": len(inventory.secrets),
        "runtime_configs": len(inventory.runtime_configs),
        "source_maps": len(inventory.source_maps),
        "routes": len(inventory.routes),
        "storage_references": len(inventory.storage_references),
        "dom_review_leads": len(inventory.dom_review_leads),
        "postmessage_leads": len(inventory.postmessage_leads),
    }
    return inventory


def scan_folder(path: Path) -> FrontendInventory:
    if not path.is_dir():
        raise ValueError(f"Input folder does not exist: {path}")
    files = sorted(
        item
        for item in path.rglob("*")
        if item.is_file() and item.suffix.lower() in SUPPORTED_SUFFIXES
    )
    combined = FrontendInventory(source_files=[str(item) for item in files])
    for file in files:
        current = scan_file(file)
        for field in (
            "findings",
            "secrets",
            "runtime_configs",
            "source_maps",
            "routes",
            "api_clients",
            "storage_references",
            "dom_review_leads",
            "postmessage_leads",
        ):
            getattr(combined, field).extend(getattr(current, field))
    return _finish(combined)


def scan_input(path: Path) -> FrontendInventory:
    return scan_folder(path) if path.is_dir() else scan_file(path)
