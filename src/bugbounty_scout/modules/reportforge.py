"""Create redacted, local-only submission drafts from existing artifacts."""

import json
import re
from hashlib import sha256
from pathlib import Path

from pydantic import ValidationError

from bugbounty_scout.config import dump_yaml, load_data
from bugbounty_scout.models import (
    AttachmentType,
    ChecklistStatus,
    EvidenceWorkspace,
    Finding,
    PlatformProfile,
    ProjectCorrelationInventory,
    Reportability,
    SubmissionAttachment,
    SubmissionChecklistItem,
    SubmissionDraft,
    SubmissionStatus,
    WorkflowManifest,
)
from bugbounty_scout.redaction import REPLACEMENTS, redact_text

WEAK_RE = re.compile(r"(?i)\b(maybe|might|could be|i think|seems like|probably)\b")
VAGUE = {"bug", "issue", "test", "finding", "vulnerability", "security issue"}


def slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "report"


def _attachment(path: str, title: str, kind: AttachmentType) -> SubmissionAttachment:
    item = SubmissionAttachment(
        id=f"attachment-{sha256((path + title).encode()).hexdigest()[:12]}",
        title=title,
        path=path,
        attachment_type=kind,
    )
    candidate = Path(path)
    if candidate.is_file():
        raw = candidate.read_bytes()
        item.sha256, item.size_bytes = sha256(raw).hexdigest(), len(raw)
    else:
        item.notes = "Referenced local attachment does not exist."
    return item


def from_evidence(path: Path) -> SubmissionDraft:
    try:
        workspace = EvidenceWorkspace.model_validate(load_data(path))
    except (ValidationError, ValueError) as exc:
        raise ValueError(f"Invalid evidence workspace: {exc}") from exc
    attachments = [
        _attachment(item.path, item.title or item.id, AttachmentType.OTHER)
        for item in workspace.evidence_items
        if item.path
    ]
    evidence = "\n".join(
        f"- {item.title or item.id}: "
        f"{redact_text(item.redacted_evidence_text or item.description)}"
        for item in workspace.evidence_items
    )
    draft = SubmissionDraft(
        id=f"submission-{slugify(workspace.title)}",
        title=workspace.title,
        vulnerability_class=workspace.finding_type,
        severity_estimate=workspace.severity_estimate,
        confidence=workspace.confidence,
        affected_assets=workspace.affected_assets,
        summary=workspace.actual_behavior,
        impact=workspace.impact,
        steps_to_reproduce=[step.action for step in workspace.reproduction_steps],
        expected_behavior=workspace.expected_behavior,
        actual_behavior=workspace.actual_behavior,
        evidence_summary=evidence,
        remediation=workspace.remediation,
        limitations="Evidence is locally organized and requires manual validation.",
        scope_notes=workspace.scope_notes,
        severity_rationale=workspace.severity_rationale,
        source_type="evidence_workspace",
        source_file=str(path),
        attachments=attachments,
        quality_warnings=[warning.message for warning in workspace.quality_warnings],
        status=(
            SubmissionStatus.READY
            if workspace.status.value == "ready"
            else SubmissionStatus.NEEDS_REVIEW
        ),
    )
    lint_draft(draft)
    return draft


def from_lead(path: Path, lead_id: str) -> SubmissionDraft:
    try:
        project = ProjectCorrelationInventory.model_validate(load_data(path))
    except (ValidationError, ValueError) as exc:
        raise ValueError(f"Invalid correlation project: {exc}") from exc
    lead = next((item for item in project.triage_leads if item.id == lead_id), None)
    if not lead:
        raise ValueError(f"Lead not found: {lead_id}")
    asset = next((x for x in project.assets if x.id == lead.affected_asset_id), None)
    affected = []
    if asset:
        affected = [f"{asset.method} {asset.host}{asset.path}".strip()]
    attachments = []
    for reference in lead.related_evidence:
        artifact = next((x for x in project.artifacts if x.id == reference), None)
        if artifact:
            attachments.append(
                _attachment(
                    artifact.path, artifact.path, AttachmentType.CORRELATION_REPORT
                )
            )
    draft = SubmissionDraft(
        id=f"submission-{slugify(lead.id)}",
        title=lead.title,
        vulnerability_class=lead.category.value,
        severity_estimate=lead.severity_estimate,
        confidence=lead.confidence,
        affected_assets=affected,
        summary=lead.reason,
        steps_to_reproduce=lead.manual_validation_steps,
        reporter_notes="\n".join(lead.suggested_evidence_to_collect),
        limitations="Correlator leads are hypotheses until manually validated.",
        source_type="correlation_lead",
        source_file=str(path),
        attachments=attachments,
        status=(
            SubmissionStatus.NEEDS_REVIEW
            if lead.reportability == Reportability.REPORT_READY
            else SubmissionStatus.BLOCKED
        ),
    )
    lint_draft(draft)
    return draft


def from_finding(path: Path) -> SubmissionDraft:
    try:
        finding = Finding.model_validate(load_data(path))
    except (ValidationError, ValueError) as exc:
        raise ValueError(f"Invalid finding: {exc}") from exc
    draft = SubmissionDraft(
        id=f"submission-{slugify(finding.id)}",
        title=finding.title,
        vulnerability_class=finding.type,
        severity_estimate=finding.severity,
        confidence=finding.confidence,
        affected_assets=[finding.asset],
        summary=finding.redacted_evidence or redact_text(finding.evidence),
        impact=finding.impact,
        evidence_summary=finding.redacted_evidence or redact_text(finding.evidence),
        remediation=finding.recommendation,
        limitations="Imported finding requires manual reproduction-step review.",
        source_type="finding",
        source_file=str(path),
        status=SubmissionStatus.NEEDS_REVIEW,
    )
    lint_draft(draft)
    return draft


def from_workflow(path: Path) -> list[SubmissionDraft]:
    root = path if path.is_dir() else path.parent
    manifest_path = path / "workflow-manifest.yml" if path.is_dir() else path
    try:
        manifest = WorkflowManifest.model_validate(load_data(manifest_path))
    except (ValidationError, ValueError) as exc:
        raise ValueError(f"Invalid workflow workspace: {exc}") from exc
    correlation = root / manifest.correlation_project
    if correlation.is_file():
        project = ProjectCorrelationInventory.model_validate(load_data(correlation))
        return [from_lead(correlation, lead.id) for lead in project.triage_leads]
    drafts = []
    for output in manifest.outputs:
        candidate = root / output.path
        if output.output_type.value == "evidence_workspace" and candidate.is_file():
            drafts.append(from_evidence(candidate))
    return drafts


def load_draft(path: Path) -> SubmissionDraft:
    if path.is_dir():
        for name in ("submission-draft.yml", "draft.yml", "report.json"):
            if (path / name).is_file():
                path = path / name
                break
    try:
        data = load_data(path)
        if "draft" in data:
            data = data["draft"]
        return SubmissionDraft.model_validate(data)
    except (ValidationError, ValueError) as exc:
        raise ValueError(f"Invalid submission draft: {exc}") from exc


def save_draft(draft: SubmissionDraft, path: Path) -> Path:
    draft.updated_at = draft.updated_at.__class__.now(draft.updated_at.tzinfo)
    path.parent.mkdir(parents=True, exist_ok=True)
    dump_yaml(draft.model_dump(mode="json"), path)
    return path


def redaction_findings(draft: SubmissionDraft) -> list[str]:
    data = json.dumps(draft.model_dump(mode="json"))
    categories = []
    labels = (
        "bearer token",
        "bearer token",
        "JWT",
        "cookie",
        "API key or session secret",
        "OAuth, CSRF, or refresh token",
        "private key",
        "email address",
        "phone number",
    )
    for (pattern, _), label in zip(REPLACEMENTS, labels, strict=True):
        if pattern.search(data):
            categories.append(
                f"Possible unredacted {label} detected; value suppressed."
            )
    return sorted(set(categories))


def lint_draft(draft: SubmissionDraft) -> tuple[list[str], list[str]]:
    blocking, warnings = [], []
    checks = (
        (not draft.affected_assets, "Missing affected asset."),
        (not draft.impact.strip(), "Missing impact."),
        (not draft.steps_to_reproduce, "Missing reproduction steps."),
        (not draft.evidence_summary.strip(), "Missing evidence for the claim."),
        (
            draft.title.strip().lower() in VAGUE or len(draft.title.split()) < 3,
            "Title is vague.",
        ),
    )
    blocking.extend(message for condition, message in checks if condition)
    if draft.severity_estimate.value in {"high", "critical"}:
        if not draft.evidence_summary.strip():
            blocking.append("High/critical severity has no evidence.")
        if not draft.impact.strip():
            blocking.append("High/critical severity has no impact.")
    redactions = redaction_findings(draft)
    if redactions:
        blocking.append("Report body may contain unredacted sensitive data.")
    for attachment in draft.attachments:
        if attachment.include_in_package and (
            not attachment.path or not Path(attachment.path).is_file()
        ):
            blocking.append(f"Referenced attachment does not exist: {attachment.title}")
    text = " ".join([draft.title, draft.summary, draft.impact, draft.reporter_notes])
    optional = (
        (bool(WEAK_RE.search(text)), "Report uses weak or speculative language."),
        (not draft.remediation.strip(), "Missing remediation."),
        (
            not draft.expected_behavior.strip() or not draft.actual_behavior.strip(),
            "Missing expected or actual behavior.",
        ),
        (not draft.scope_notes.strip(), "No scope notes."),
        (not draft.severity_rationale.strip(), "No severity rationale."),
        (
            draft.severity_estimate.value == "info",
            "Report appears informational.",
        ),
        (
            draft.status != SubmissionStatus.READY,
            "Report needs manual validation.",
        ),
    )
    warnings.extend(message for condition, message in optional if condition)
    draft.redaction_warnings = redactions
    draft.quality_warnings = list(
        dict.fromkeys(draft.quality_warnings + blocking + warnings)
    )
    draft.status = (
        SubmissionStatus.BLOCKED
        if blocking
        else SubmissionStatus.NEEDS_REVIEW
        if warnings
        else SubmissionStatus.READY
    )
    return list(dict.fromkeys(blocking)), list(dict.fromkeys(warnings))


def checklist(draft: SubmissionDraft) -> list[SubmissionChecklistItem]:
    blocking, _ = lint_draft(draft)
    specs = [
        ("scope", "Asset is in scope.", True, False),
        (
            "secrets",
            "Report does not include real credentials.",
            True,
            not draft.redaction_warnings,
        ),
        (
            "tokens",
            "Report does not include raw cookies/tokens.",
            True,
            not draft.redaction_warnings,
        ),
        (
            "reproduction",
            "Steps are reproducible.",
            True,
            bool(draft.steps_to_reproduce),
        ),
        ("impact", "Impact is clear.", True, bool(draft.impact)),
        (
            "evidence",
            "Evidence supports the claim.",
            True,
            bool(draft.evidence_summary),
        ),
        ("severity", "Severity is justified.", False, bool(draft.severity_rationale)),
        (
            "behavior",
            "Expected and actual behavior are clear.",
            False,
            bool(draft.expected_behavior and draft.actual_behavior),
        ),
        (
            "attachments",
            "Attachments exist.",
            True,
            not any("attachment" in x.lower() for x in blocking),
        ),
        ("screenshots", "Sensitive screenshots are redacted.", True, False),
        ("rules", "Program rules were reviewed manually.", True, False),
        ("safety", "No destructive testing was performed.", True, False),
        ("automation", "No prohibited automation was used.", True, False),
        ("exploit", "No live exploit automation is included.", True, True),
    ]
    return [
        SubmissionChecklistItem(
            id=f"check-{category}",
            category=category,
            text=text,
            status=ChecklistStatus.PASS if passed else ChecklistStatus.WARNING,
            blocking=blocking_item,
            recommendation=(
                "Manually confirm this item before submission."
                if not passed
                else "Confirmed from the local draft; still review manually."
            ),
        )
        for category, text, blocking_item, passed in specs
    ]


def render_checklist(draft: SubmissionDraft, format: str) -> str:
    items = checklist(draft)
    if format == "json":
        return json.dumps([item.model_dump(mode="json") for item in items], indent=2)
    return (
        "# Final submission checklist\n\n"
        + "\n".join(
            f"- [{'x' if item.status == ChecklistStatus.PASS else ' '}] {item.text} "
            f"— {item.recommendation}"
            for item in items
        )
        + "\n"
    )


SECTIONS = {
    "generic": (
        "Summary",
        "Affected asset",
        "Vulnerability class",
        "Severity",
        "Impact",
        "Steps to reproduce",
        "Expected behavior",
        "Actual behavior",
        "Evidence",
        "Remediation",
        "Notes / limitations",
    ),
    "hackerone": (
        "Summary",
        "Steps to Reproduce",
        "Impact",
        "Supporting Material / References",
        "Suggested Remediation",
        "Notes",
    ),
    "bugcrowd": (
        "Vulnerability Summary",
        "Technical Details",
        "Steps to Reproduce",
        "Business Impact",
        "Remediation",
        "Attachments",
        "Additional Notes",
    ),
    "intigriti": (
        "Description",
        "Impact",
        "Reproduction Steps",
        "Proof of Concept / Evidence",
        "Suggested Fix",
        "Additional Context",
    ),
    "yeswehack": (
        "Summary",
        "Affected Asset",
        "Technical Details",
        "Reproduction Steps",
        "Impact",
        "Remediation",
        "Evidence",
    ),
    "github_security_advisory": (
        "Summary",
        "Affected Products",
        "Severity",
        "Impact",
        "Reproduction Steps",
        "Evidence",
        "Remediation",
        "Credits / Notes",
    ),
    "internal": (
        "Executive Summary",
        "Technical Summary",
        "Affected Systems",
        "Risk Rating",
        "Evidence",
        "Reproduction Steps",
        "Remediation",
        "Validation Notes",
    ),
}


def render_markdown(
    draft: SubmissionDraft, profile: PlatformProfile | str | None = None
) -> str:
    profile = PlatformProfile(profile or draft.platform_profile)
    draft.platform_profile = profile
    values = {
        "summary": draft.summary,
        "affected": "\n".join(f"- `{x}`" for x in draft.affected_assets),
        "class": draft.vulnerability_class,
        "severity": f"{draft.severity_estimate.value.title()} — {draft.severity_rationale}",
        "impact": draft.impact,
        "steps": "\n".join(
            f"{i}. {x}" for i, x in enumerate(draft.steps_to_reproduce, 1)
        ),
        "expected": draft.expected_behavior,
        "actual": draft.actual_behavior,
        "evidence": draft.evidence_summary,
        "remediation": draft.remediation,
        "notes": "\n\n".join(
            filter(None, [draft.limitations, draft.reporter_notes, draft.scope_notes])
        ),
        "attachments": "\n".join(
            f"- `{x.path}` — {x.title}" for x in draft.attachments
        ),
    }
    mapping = {
        "Summary": "summary",
        "Vulnerability Summary": "summary",
        "Description": "summary",
        "Executive Summary": "summary",
        "Affected asset": "affected",
        "Affected Asset": "affected",
        "Affected Systems": "affected",
        "Affected Products": "affected",
        "Vulnerability class": "class",
        "Technical Details": "class",
        "Technical Summary": "class",
        "Severity": "severity",
        "Risk Rating": "severity",
        "Impact": "impact",
        "Business Impact": "impact",
        "Steps to reproduce": "steps",
        "Steps to Reproduce": "steps",
        "Reproduction Steps": "steps",
        "Expected behavior": "expected",
        "Actual behavior": "actual",
        "Evidence": "evidence",
        "Supporting Material / References": "evidence",
        "Proof of Concept / Evidence": "evidence",
        "Remediation": "remediation",
        "Suggested Remediation": "remediation",
        "Suggested Fix": "remediation",
        "Notes / limitations": "notes",
        "Notes": "notes",
        "Additional Notes": "notes",
        "Additional Context": "notes",
        "Validation Notes": "notes",
        "Credits / Notes": "notes",
        "Attachments": "attachments",
    }
    output = [f"# {redact_text(draft.title)}", ""]
    for section in SECTIONS[profile.value]:
        output.extend(
            [
                f"## {section}",
                "",
                redact_text(values.get(mapping[section], "") or "_Not provided._"),
                "",
            ]
        )
    return "\n".join(output)


def render_json(draft: SubmissionDraft) -> str:
    data = draft.model_dump(mode="json")
    data["quality"] = {
        "blocking": lint_draft(draft)[0],
        "warnings": lint_draft(draft)[1],
    }
    return json.dumps(json.loads(redact_text(json.dumps(data))), indent=2)
