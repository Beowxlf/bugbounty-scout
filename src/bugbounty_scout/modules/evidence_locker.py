"""Local-only evidence workspace management and redacted exports."""

import json
import re
from hashlib import sha256
from pathlib import Path

from pydantic import ValidationError

from bugbounty_scout.config import dump_yaml, load_data
from bugbounty_scout.models import (
    EvidenceItem,
    EvidenceType,
    EvidenceWorkspace,
    ReproductionStep,
    Severity,
    utc_now,
)
from bugbounty_scout.redaction import redact_text

MAX_TEXT_BYTES = 1_000_000


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "finding"


def new_workspace(title: str) -> EvidenceWorkspace:
    title = title.strip()
    if not title:
        raise ValueError("Evidence workspace title must not be blank")
    return EvidenceWorkspace(id=f"evidence-{slugify(title)}", title=title)


def load_workspace(path: Path) -> EvidenceWorkspace:
    if not path.is_file():
        raise ValueError(f"Evidence workspace does not exist: {path}")
    try:
        return EvidenceWorkspace.model_validate(load_data(path))
    except (ValidationError, OSError) as exc:
        raise ValueError(f"Invalid evidence workspace: {exc}") from exc


def save_workspace(workspace: EvidenceWorkspace, path: Path) -> Path:
    workspace.updated_at = utc_now()
    dump_yaml(workspace.model_dump(mode="json"), path)
    return path


def _file_text(path: Path) -> str:
    if path.stat().st_size > MAX_TEXT_BYTES:
        return ""
    data = path.read_bytes()
    if not data:
        return ""
    if b"\x00" in data:
        return ""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return ""


def add_file(
    workspace: EvidenceWorkspace,
    path: Path,
    evidence_type: EvidenceType | str,
    *,
    title: str = "",
    description: str = "",
) -> EvidenceItem:
    if not path.is_file():
        raise ValueError(f"Evidence file does not exist: {path}")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"Could not read evidence file {path}: {exc}") from exc
    text = _file_text(path)
    redacted = redact_text(text)
    identifier = sha256(
        (str(path) + str(len(workspace.evidence_items))).encode()
    ).hexdigest()[:12]
    item = EvidenceItem(
        id=f"evidence-{identifier}",
        type=evidence_type,
        title=title or path.name,
        description=description or f"Local file ({len(data)} bytes)",
        path=str(path),
        sha256=sha256(data).hexdigest(),
        contains_sensitive_data=bool(text and redacted != text),
        evidence_text="",
        redacted_evidence_text=redacted,
    )
    workspace.evidence_items.append(item)
    return item


def add_note(workspace: EvidenceWorkspace, title: str, text: str) -> EvidenceItem:
    redacted = redact_text(text)
    identifier = sha256(
        (title + text + str(len(workspace.evidence_items))).encode()
    ).hexdigest()[:12]
    item = EvidenceItem(
        id=f"evidence-{identifier}",
        type=EvidenceType.NOTE,
        title=title,
        contains_sensitive_data=redacted != text,
        redacted_evidence_text=redacted,
    )
    workspace.evidence_items.append(item)
    return item


def add_step(
    workspace: EvidenceWorkspace,
    action: str,
    expected: str,
    actual: str,
    evidence_reference: str = "",
) -> ReproductionStep:
    order = len(workspace.reproduction_steps) + 1
    step = ReproductionStep(
        id=f"step-{order:03d}",
        order=order,
        action=action,
        expected_result=expected,
        actual_result=actual,
        evidence_reference=evidence_reference,
    )
    workspace.reproduction_steps.append(step)
    return step


def render_json(workspace: EvidenceWorkspace) -> str:
    data = workspace.model_dump(mode="json")
    for item in data["evidence_items"]:
        item["evidence_text"] = ""
        item["redacted_evidence_text"] = redact_text(item["redacted_evidence_text"])
    return json.dumps(data, indent=2)


def _value(value: str) -> str:
    return redact_text(value) if value.strip() else "_Not provided._"


def render_markdown(workspace: EvidenceWorkspace) -> str:
    assets = "\n".join(f"- `{redact_text(x)}`" for x in workspace.affected_assets)
    steps = "\n".join(
        f"{step.order}. **Action:** {_value(step.action)}\n"
        f"   - Expected: {_value(step.expected_result)}\n"
        f"   - Actual: {_value(step.actual_result)}\n"
        f"   - Evidence: `{step.evidence_reference or 'not linked'}`"
        for step in workspace.reproduction_steps
    )
    items = "\n".join(
        f"- **{_value(item.title)}** (`{item.type.value}`) — "
        f"`{item.path or 'inline note'}`"
        for item in workspace.evidence_items
    )
    hashes = "\n".join(
        f"- `{item.id}`: `{item.sha256}`"
        for item in workspace.evidence_items
        if item.sha256
    )
    snippets = "\n\n".join(
        f"### {_value(item.title)}\n\n```text\n"
        f"{redact_text(item.redacted_evidence_text)[:4000]}\n```"
        for item in workspace.evidence_items
        if item.redacted_evidence_text
    )
    warnings = "\n".join(
        f"- **{warning.category.value}**: {_value(warning.message)}"
        for warning in workspace.quality_warnings
    )
    return redact_text(
        f"""# {workspace.title}

## Summary

- **Workspace ID:** `{workspace.id}`
- **Status:** {workspace.status.value}
- **Finding type:** {_value(workspace.finding_type)}
- **Confidence:** {workspace.confidence.value}

## Affected assets

{assets or "_None provided._"}

## Scope notes

{_value(workspace.scope_notes)}

## Severity estimate and rationale

**{workspace.severity_estimate.value.title()}** — {_value(workspace.severity_rationale)}

## Actor/Object context

- **Actor:** {_value(workspace.actor_context)}
- **Object:** {_value(workspace.object_context)}

## Expected behavior

{_value(workspace.expected_behavior)}

## Actual behavior

{_value(workspace.actual_behavior)}

## Impact

{_value(workspace.impact)}

## Reproduction steps

{steps or "_None provided._"}

## Evidence items

{items or "_None provided._"}

## Evidence hashes

{hashes or "_No file hashes._"}

## Redacted proof snippets

{snippets or "_No text proof snippets._"}

## Remediation

{_value(workspace.remediation)}

## Quality warnings

{warnings or "_No quality warnings._"}

## Redaction notice

Evidence text is redacted by default. Original local files are not copied into
this report and should be reviewed before sharing.

## Limitations

This local, passive/manual workspace does not send or replay requests, validate
secrets, generate payloads, fuzz, scan, or prove exploitability.
"""
    )


def set_severity(
    workspace: EvidenceWorkspace, severity: Severity | str, rationale: str
) -> None:
    workspace.severity_estimate = Severity(severity)
    workspace.severity_rationale = rationale
