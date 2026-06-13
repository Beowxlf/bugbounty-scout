"""Finding report generation."""

from pathlib import Path

from pydantic import ValidationError

from bugbounty_scout.config import load_data
from bugbounty_scout.models import Finding
from bugbounty_scout.redaction import redact_text


def load_finding(path: Path) -> Finding:
    try:
        return Finding.model_validate(load_data(path))
    except ValidationError as exc:
        raise ValueError(f"Invalid finding: {exc}") from exc


def finding_warnings(finding: Finding) -> list[str]:
    warnings = []
    if not finding.evidence.strip() and not finding.redacted_evidence.strip():
        warnings.append("Finding has no evidence.")
    if not finding.impact.strip():
        warnings.append("Finding has no impact statement.")
    return warnings


def render_markdown(finding: Finding) -> str:
    """Render a finding while ensuring all free-text output is redacted."""
    evidence = finding.redacted_evidence or redact_text(finding.evidence)
    values = {
        "title": finding.title,
        "id": finding.id,
        "type": finding.type,
        "severity": finding.severity.value.title(),
        "confidence": finding.confidence.value.title(),
        "asset": finding.asset,
        "source": finding.source_module,
        "created": finding.created_at.isoformat(),
        "evidence": evidence or "_Not provided._",
        "impact": finding.impact or "_Not provided._",
        "recommendation": finding.recommendation or "_Not provided._",
    }
    values = {key: redact_text(value) for key, value in values.items()}
    return (
        f"# {values['title']}\n\n"
        f"- **Finding ID:** {values['id']}\n"
        f"- **Type:** {values['type']}\n"
        f"- **Severity:** {values['severity']}\n"
        f"- **Confidence:** {values['confidence']}\n"
        f"- **Asset:** {values['asset']}\n"
        f"- **Source module:** {values['source']}\n"
        f"- **Created:** {values['created']}\n\n"
        f"## Evidence\n\n{values['evidence']}\n\n"
        f"## Impact\n\n{values['impact']}\n\n"
        f"## Recommendation\n\n{values['recommendation']}\n"
    )


def export_markdown(finding: Finding, output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_markdown(finding), encoding="utf-8")
    return output
