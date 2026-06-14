import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from bugbounty_scout.cli import app
from bugbounty_scout.models import PlatformProfile, SubmissionStatus
from bugbounty_scout.modules.reportforge import (
    from_evidence,
    from_finding,
    from_lead,
    from_workflow,
    lint_draft,
    load_draft,
    redaction_findings,
    render_checklist,
    render_json,
    render_markdown,
)
from bugbounty_scout.modules.submission_packager import build_package

FIXTURES = Path("fixtures/submit")


def test_submission_draft_sources():
    evidence = from_evidence(FIXTURES / "fake_evidence_workspace.yml")
    assert evidence.vulnerability_class == "idor"
    assert evidence.steps_to_reproduce
    lead = from_lead(FIXTURES / "fake_correlation_project.yml", "fake-lead-001")
    assert lead.status == SubmissionStatus.BLOCKED
    assert lead.affected_assets
    assert from_workflow(FIXTURES / "fake_workflow_workspace")
    assert from_finding(FIXTURES / "fake_finding.yml").source_type == "finding"


@pytest.mark.parametrize(
    ("profile", "heading"),
    [
        ("generic", "## Affected asset"),
        ("hackerone", "## Supporting Material / References"),
        ("bugcrowd", "## Business Impact"),
        ("intigriti", "## Proof of Concept / Evidence"),
        ("yeswehack", "## Affected Asset"),
        ("internal", "## Executive Summary"),
    ],
)
def test_platform_exports(profile, heading):
    draft = load_draft(FIXTURES / "fake_draft.yml")
    assert heading in render_markdown(draft, PlatformProfile(profile))
    assert "example.test" in render_json(draft)


def test_lint_redaction_checklist_and_package(tmp_path):
    draft = load_draft(FIXTURES / "fake_draft.yml")
    blocking, warnings = lint_draft(draft)
    assert not blocking
    assert "Report needs manual validation." in warnings
    assert "Program rules were reviewed manually." in render_checklist(
        draft, "markdown"
    )
    assert json.loads(render_checklist(draft, "json"))
    package = build_package(draft, tmp_path / "submission-package", "hackerone")
    assert Path(package.report_markdown).is_file()
    assert (tmp_path / "submission-package/attachment-manifest.json").is_file()
    assert (tmp_path / "submission-package/quality-warnings.json").is_file()


def test_missing_attachment_and_sensitive_values_are_safe(tmp_path):
    draft = load_draft(FIXTURES / "fake_draft.yml")
    draft.attachments[2].include_in_package = True
    blocking, _ = lint_draft(draft)
    assert any("does not exist" in item for item in blocking)
    secret = "Bearer faketoken-not-real"
    draft.summary = secret
    warnings = redaction_findings(draft)
    assert warnings and secret not in json.dumps(warnings)


def test_malformed_inputs(tmp_path):
    malformed = tmp_path / "bad.yml"
    malformed.write_text("title: [", encoding="utf-8")
    with pytest.raises(ValueError):
        load_draft(malformed)
    with pytest.raises(ValueError):
        from_evidence(malformed)


def test_submit_cli_workflows(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    root = Path(__file__).parents[1]
    runner = CliRunner()
    draft = root / "fixtures/submit/fake_draft.yml"
    evidence = root / "fixtures/submit/fake_evidence_workspace.yml"
    assert runner.invoke(app, ["submit", "--help"]).exit_code == 0
    assert (
        runner.invoke(
            app, ["submit", "from-evidence", str(evidence), "--output", "draft.yml"]
        ).exit_code
        == 0
    )
    assert runner.invoke(app, ["submit", "preview", str(draft)]).exit_code == 0
    assert (
        runner.invoke(
            app, ["submit", "export", str(draft), "--format", "markdown"]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            app, ["submit", "package", str(draft), "--platform", "generic"]
        ).exit_code
        == 0
    )
