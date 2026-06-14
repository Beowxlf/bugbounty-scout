import json
from hashlib import sha256
from pathlib import Path

import pytest
from typer.testing import CliRunner

from bugbounty_scout.cli import app
from bugbounty_scout.models import EvidenceType
from bugbounty_scout.modules.evidence_locker import (
    add_file,
    add_note,
    add_step,
    load_workspace,
    new_workspace,
    render_json,
    render_markdown,
    save_workspace,
    set_severity,
)
from bugbounty_scout.modules.report_quality import lint_workspace

FIXTURES = Path("fixtures/evidence")


def test_workspace_initialization_and_round_trip(tmp_path: Path) -> None:
    workspace = new_workspace("User A can access User B invoice")
    path = tmp_path / "workspace.yml"
    save_workspace(workspace, path)
    loaded = load_workspace(path)
    assert loaded.status.value == "draft"
    assert loaded.evidence_items == []
    assert "no requests" in loaded.safety_notice


def test_add_note_request_response_hash_redaction_and_sensitive_detection() -> None:
    workspace = new_workspace("Evidence test")
    note = add_note(workspace, "Note", "email=user@example.test")
    request = add_file(workspace, FIXTURES / "fake_request.txt", "raw_request")
    response = add_file(workspace, FIXTURES / "fake_response.txt", "raw_response")
    assert note.contains_sensitive_data
    assert (
        request.sha256
        == sha256((FIXTURES / "fake_request.txt").read_bytes()).hexdigest()
    )
    assert request.contains_sensitive_data and response.contains_sensitive_data
    assert "fake-bearer" not in request.redacted_evidence_text
    assert "user.b@example.test" not in response.redacted_evidence_text


def test_screenshot_arbitrary_empty_binary_and_missing_files(tmp_path: Path) -> None:
    workspace = new_workspace("Files")
    image = tmp_path / "proof.png"
    image.write_bytes(b"\x89PNG\x00synthetic")
    screenshot = add_file(workspace, image, EvidenceType.SCREENSHOT)
    assert screenshot.redacted_evidence_text == ""
    empty = tmp_path / "empty.txt"
    empty.write_text("", encoding="utf-8")
    assert add_file(workspace, empty, "other").sha256 == sha256(b"").hexdigest()
    with pytest.raises(ValueError, match="does not exist"):
        add_file(workspace, tmp_path / "missing", "other")


def test_steps_and_setters() -> None:
    workspace = new_workspace("Behavior test")
    step = add_step(workspace, "Act", "Denied", "Allowed", "evidence-1")
    workspace.impact = "Cross-user metadata exposure."
    workspace.expected_behavior = "Denied"
    workspace.actual_behavior = "Allowed"
    set_severity(workspace, "medium", "Bounded metadata impact.")
    assert step.order == 1 and step.evidence_reference == "evidence-1"
    assert workspace.severity_estimate.value == "medium"


def test_markdown_json_exports_are_complete_and_redacted() -> None:
    workspace = load_workspace(FIXTURES / "fake_workspace.yml")
    markdown = render_markdown(workspace)
    structured = json.loads(render_json(workspace))
    for heading in (
        "Summary",
        "Affected assets",
        "Scope notes",
        "Severity estimate and rationale",
        "Actor/Object context",
        "Expected behavior",
        "Actual behavior",
        "Impact",
        "Reproduction steps",
        "Evidence items",
        "Evidence hashes",
        "Redacted proof snippets",
        "Remediation",
        "Quality warnings",
        "Redaction notice",
        "Limitations",
    ):
        assert f"## {heading}" in markdown
    assert structured["evidence_items"][0]["evidence_text"] == ""


def test_quality_warnings_weak_language_unsupported_and_unredacted() -> None:
    missing = load_workspace(FIXTURES / "fake_workspace_missing_impact.yml")
    categories = {item.category.value for item in lint_workspace(missing)}
    assert {
        "missing_impact",
        "missing_evidence",
        "weak_language",
        "unsupported_severity",
        "vague_title",
    } <= categories
    unsafe = load_workspace(FIXTURES / "fake_workspace_unredacted.yml")
    unsafe_categories = {item.category.value for item in lint_workspace(unsafe)}
    assert {"unredacted_token", "pii_exposure"} <= unsafe_categories


def test_cli_workflow_and_legacy_report_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(
        app, ["evidence", "init", "User A can access User B invoice"]
    )
    assert result.exit_code == 0
    workspace = tmp_path / "user-a-can-access-user-b-invoice-evidence.yml"
    note = runner.invoke(
        app,
        [
            "evidence",
            "add-note",
            str(workspace),
            "--title",
            "Observation",
            "--text",
            "Synthetic note",
        ],
    )
    assert note.exit_code == 0
    listing = runner.invoke(app, ["evidence", "list", str(workspace)])
    assert "Observation" in listing.output
    exported = runner.invoke(
        app, ["evidence", "export", str(workspace), "--format", "json"]
    )
    assert exported.exit_code == 0 and '"evidence_items"' in exported.output
    legacy = Path(__file__).parent.parent / "fixtures/fake_finding.yml"
    report = runner.invoke(
        app, ["report", "export", str(legacy), "--output", str(tmp_path / "legacy.md")]
    )
    assert report.exit_code == 0
