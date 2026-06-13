from pathlib import Path

from bugbounty_scout.models import Finding
from bugbounty_scout.reporting import export_markdown, finding_warnings


def test_markdown_export_is_redacted(tmp_path: Path) -> None:
    finding = Finding(
        id="BBS-001",
        title="Synthetic finding",
        type="information-disclosure",
        severity="medium",
        confidence="high",
        asset="https://example.test",
        evidence="Authorization: Bearer fake-sensitive-token",
        impact="Synthetic users could observe metadata.",
        recommendation="Return only required fields.",
        source_module="manual",
    )
    output = export_markdown(finding, tmp_path / "report.md")
    report = output.read_text(encoding="utf-8")
    assert "# Synthetic finding" in report
    assert "fake-sensitive-token" not in report
    assert "<redacted-token>" in report
    assert finding_warnings(finding) == []


def test_missing_evidence_and_impact_warn() -> None:
    finding = Finding(
        id="BBS-002",
        title="Incomplete synthetic finding",
        type="test",
        severity="info",
        confidence="low",
        asset="https://example.test",
        source_module="manual",
    )
    assert len(finding_warnings(finding)) == 2
