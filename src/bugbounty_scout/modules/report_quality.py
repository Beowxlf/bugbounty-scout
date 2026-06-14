"""Conservative report quality checks for evidence workspaces."""

import re
from hashlib import sha256

from bugbounty_scout.models import (
    EvidenceWorkspace,
    ReportQualityWarning,
    Severity,
)
from bugbounty_scout.redaction import redact_text

WEAK_RE = re.compile(
    r"(?i)\b(maybe|might|could be|i think|seems like|potentially critical|"
    r"maybe vulnerable|should be critical|probably)\b"
)
VAGUE_TITLES = {"test", "bug", "issue", "vulnerability", "security issue", "finding"}


def lint_workspace(workspace: EvidenceWorkspace) -> list[ReportQualityWarning]:
    warnings: list[ReportQualityWarning] = []

    def add(category, message, recommendation, field, severity="low"):
        key = f"{category}:{field}:{message}"
        warnings.append(
            ReportQualityWarning(
                id=f"quality-{sha256(key.encode()).hexdigest()[:12]}",
                category=category,
                severity=severity,
                message=message,
                recommendation=recommendation,
                field=field,
            )
        )

    checks = (
        (
            not workspace.impact.strip(),
            "missing_impact",
            "Impact is missing.",
            "Describe concrete user or business impact.",
            "impact",
        ),
        (
            not workspace.affected_assets,
            "missing_affected_asset",
            "No affected asset is listed.",
            "Add the exact in-scope asset.",
            "affected_assets",
        ),
        (
            not workspace.reproduction_steps,
            "missing_reproduction_steps",
            "No reproduction steps are present.",
            "Add ordered, minimal manual steps.",
            "reproduction_steps",
        ),
        (
            not workspace.evidence_items,
            "missing_evidence",
            "No evidence is attached.",
            "Attach redacted proof or a local evidence reference.",
            "evidence_items",
        ),
        (
            not workspace.expected_behavior.strip()
            or not workspace.actual_behavior.strip(),
            "missing_expected_actual",
            "Expected or actual behavior is missing.",
            "State both expected and observed behavior.",
            "expected_behavior",
        ),
        (
            not workspace.remediation.strip(),
            "no_remediation",
            "No remediation guidance is present.",
            "Add concise remediation guidance.",
            "remediation",
        ),
        (
            not workspace.scope_notes.strip(),
            "no_scope_notes",
            "No scope notes are present.",
            "Document authorization and relevant program constraints.",
            "scope_notes",
        ),
    )
    for condition, category, message, recommendation, field in checks:
        if condition:
            add(category, message, recommendation, field)
    if not workspace.severity_rationale.strip():
        add(
            "unsupported_severity",
            "Severity has no rationale.",
            "Tie severity to demonstrated impact and evidence.",
            "severity_rationale",
        )
    if (
        workspace.title.strip().lower() in VAGUE_TITLES
        or len(workspace.title.split()) < 3
    ):
        add(
            "vague_title",
            "Title may be too vague.",
            "Name the actor, action, object, and consequence.",
            "title",
        )
    text_fields = " ".join(
        [
            workspace.title,
            workspace.impact,
            workspace.severity_rationale,
            workspace.expected_behavior,
            workspace.actual_behavior,
        ]
    )
    if WEAK_RE.search(text_fields):
        add(
            "weak_language",
            "Report uses uncertain or speculative wording.",
            "Replace speculation with observed, bounded facts.",
            "report_text",
        )
    severe = workspace.severity_estimate in {Severity.HIGH, Severity.CRITICAL}
    unsupported_kind = any(
        phrase in text_fields.lower()
        for phrase in ("missing header", "public identifier", "source map")
    )
    if severe and (
        not workspace.impact or not workspace.evidence_items or unsupported_kind
    ):
        add(
            "unsupported_severity",
            "High/critical severity is not supported by the current impact and proof.",
            "Lower the estimate or add concrete evidence and impact.",
            "severity_estimate",
            "medium",
        )
    for item in workspace.evidence_items:
        text = item.evidence_text or item.redacted_evidence_text
        if text and redact_text(text) != text:
            lowered = text.lower()
            categories = set()
            if "cookie" in lowered:
                categories.add("unredacted_cookie")
            if "bearer" in lowered or "eyj" in lowered:
                categories.add("unredacted_token")
            if not categories:
                categories.add("unredacted_secret")
            for category in categories:
                add(
                    category,
                    f"Evidence item {item.id} may contain unredacted sensitive data.",
                    "Use the redacted evidence text and review before sharing.",
                    "evidence_items",
                    "medium",
                )
        if re.search(r"\b[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}\b", text):
            add(
                "pii_exposure",
                f"Evidence item {item.id} may contain PII.",
                "Redact personal data unless strictly necessary and authorized.",
                "evidence_items",
                "medium",
            )
    add(
        "needs_manual_validation",
        "Automated linting cannot validate scope, exploitability, or severity.",
        "Manually review all evidence and claims before submission.",
        "workspace",
        "info",
    )
    workspace.quality_warnings = warnings
    return warnings
