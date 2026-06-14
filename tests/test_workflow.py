import hashlib
import json
import shutil
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from bugbounty_scout.cli import app
from bugbounty_scout.models import WorkflowInputType, WorkflowStepStatus
from bugbounty_scout.modules.workflow import (
    MARKER,
    classify,
    clean,
    detect,
    initialize_workspace,
    load_manifest,
    render_report,
    render_summary,
    run,
)

runner = CliRunner()
FIXTURES = Path("fixtures/workflow/fake_inputs")


def populate(root: Path) -> None:
    for source in FIXTURES.rglob("*"):
        if source.is_file():
            destination = root / "inputs" / source.relative_to(FIXTURES)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)


def test_init_layout_readme_and_marker(tmp_path):
    root = tmp_path / "project"
    manifest = initialize_workspace(root)
    expected = [
        "inputs/har",
        "inputs/frontend",
        "inputs/graphql",
        "inputs/requests",
        "inputs/responses",
        "inputs/inventories",
        "inputs/evidence",
        "inputs/authz",
        "inputs/other",
        "outputs/har",
        "outputs/endpoints",
        "outputs/frontend",
        "outputs/auth_surface",
        "outputs/graphql",
        "outputs/paramforge",
        "outputs/correlate",
        "reports",
        "logs",
        "scope.yml",
        "workflow.yml",
        "README.md",
        MARKER,
    ]
    assert all((root / item).exists() for item in expected)
    assert "No live requests" in (root / "README.md").read_text()
    assert load_manifest(root).id == manifest.id


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("har/fake.har", WorkflowInputType.HAR),
        ("frontend/fake.js", WorkflowInputType.JAVASCRIPT),
        ("frontend/fake.html", WorkflowInputType.HTML),
        ("frontend/fake.js.map", WorkflowInputType.SOURCE_MAP),
        ("graphql/fake.graphql", WorkflowInputType.GRAPHQL),
        ("inventories/endpoint-inventory.json", WorkflowInputType.ENDPOINT_INVENTORY),
        ("evidence/evidence-workspace.yml", WorkflowInputType.EVIDENCE_WORKSPACE),
        ("other/unknown.bin", WorkflowInputType.UNKNOWN),
    ],
)
def test_classification(name, expected):
    assert classify(FIXTURES / name)[0] == expected


def test_detect_hash_and_unknown(tmp_path):
    root = tmp_path / "project"
    initialize_workspace(root)
    populate(root)
    manifest, _ = detect(root)
    unknown = next(
        item for item in manifest.inputs if item.path.endswith("unknown.bin")
    )
    assert unknown.input_type == WorkflowInputType.UNKNOWN
    source = root / unknown.path
    assert unknown.sha256 == hashlib.sha256(source.read_bytes()).hexdigest()


def test_full_run_outputs_summary_and_reports(tmp_path):
    root = tmp_path / "project"
    initialize_workspace(root)
    populate(root)
    manifest = run(root)
    assert any(step.status == WorkflowStepStatus.COMPLETED for step in manifest.steps)
    assert (root / "outputs/endpoints/endpoint-inventory.json").is_file()
    assert (root / "outputs/frontend/frontend-inventory.json").is_file()
    assert (root / "outputs/graphql/graphql-inventory.json").is_file()
    assert (root / "outputs/paramforge/paramforge-inventory.json").is_file()
    assert (root / "outputs/correlate/correlation-project.yml").is_file()
    assert (root / "reports/project-summary.md").is_file()
    assert "# Project summary" in render_summary(manifest)
    assert "Referenced module artifacts" in render_report(manifest)
    assert json.loads(render_report(manifest, "json"))["summary"]["total_inputs"]


def test_partial_run_records_skips(tmp_path):
    root = tmp_path / "partial"
    initialize_workspace(root)
    (root / "inputs/other/note.txt").write_text("synthetic note")
    manifest = run(root)
    assert any(step.status == WorkflowStepStatus.SKIPPED for step in manifest.steps)
    assert all(
        step.skipped_reason
        for step in manifest.steps
        if step.status == WorkflowStepStatus.SKIPPED
    )


def test_failed_step_does_not_abort(monkeypatch, tmp_path):
    root = tmp_path / "project"
    initialize_workspace(root)
    populate(root)

    def fail(_):
        raise RuntimeError("synthetic isolated failure")

    monkeypatch.setattr("bugbounty_scout.modules.workflow.analyze_har", fail)
    manifest = run(root)
    assert manifest.steps[0].status == WorkflowStepStatus.FAILED
    assert manifest.steps[-1].status == WorkflowStepStatus.COMPLETED


def test_clean_outputs_and_safety(tmp_path):
    root = tmp_path / "project"
    initialize_workspace(root)
    (root / "inputs/other/keep.txt").write_text("keep")
    (root / "outputs/har/remove.txt").write_text("remove")
    clean(root, outputs_only=True)
    assert (root / "inputs/other/keep.txt").is_file()
    assert not (root / "outputs/har/remove.txt").exists()
    assert load_manifest(root).outputs == []
    arbitrary = tmp_path / "arbitrary"
    arbitrary.mkdir()
    with pytest.raises(ValueError, match="safety marker"):
        clean(arbitrary)


def test_cli_workflow_and_demo_integration(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert runner.invoke(app, ["workflow", "init", "cli-project"]).exit_code == 0
    assert runner.invoke(app, ["workflow", "detect", "cli-project"]).exit_code == 0
    assert runner.invoke(app, ["workflow", "status", "cli-project"]).exit_code == 0
    assert (
        runner.invoke(
            app, ["workflow", "manifest", "cli-project", "--format", "json"]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            app, ["workflow", "summary", "cli-project", "--format", "markdown"]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            app, ["workflow", "report", "cli-project", "--format", "json"]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            app, ["workflow", "clean", "cli-project", "--outputs-only"]
        ).exit_code
        == 0
    )
    assert runner.invoke(app, ["demo", "init", "demo"]).exit_code == 0
    assert (tmp_path / "demo" / MARKER).is_file()
    assert runner.invoke(app, ["workflow", "detect", "demo"]).exit_code == 0
    assert runner.invoke(app, ["workflow", "run", "demo"]).exit_code == 0


def test_manifest_is_valid_yaml(tmp_path):
    root = tmp_path / "project"
    initialize_workspace(root)
    assert (
        yaml.safe_load((root / "workflow.yml").read_text())["project_name"] == "project"
    )
