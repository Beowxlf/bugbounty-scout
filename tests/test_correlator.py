import json
from pathlib import Path

from typer.testing import CliRunner

from bugbounty_scout.cli import app
from bugbounty_scout.models import (
    ArtifactType,
    ProjectCorrelationInventory,
    Reportability,
)
from bugbounty_scout.modules.correlator import (
    artifact_from_path,
    build,
    detect_artifact_type,
    discover,
    load_project,
    render_checklist,
    render_json,
    render_leads,
    render_markdown,
    save,
    score,
)

ROOT = Path("fixtures/correlate")


def project():
    artifacts = [
        artifact_from_path(x)[0] for x in discover(ROOT / "fake_project_folder")
    ]
    return build(
        ProjectCorrelationInventory(project_name="Synthetic", artifacts=artifacts)
    )


def test_discovery_detection_hash_parsing_and_markdown_tolerance(tmp_path):
    paths = discover(ROOT / "fake_project_folder")
    assert len(paths) >= 9
    artifact, data = artifact_from_path(ROOT / "fake_endpoint_inventory.json")
    assert artifact.artifact_type == ArtifactType.ENDPOINT_INVENTORY
    assert len(artifact.sha256) == 64 and artifact.parsed and data["endpoints"]
    note = tmp_path / "report.md"
    note.write_text("# Safe report")
    assert artifact_from_path(note)[0].artifact_type == ArtifactType.MARKDOWN_REPORT
    bad = tmp_path / "bad.json"
    bad.write_text("{")
    assert not artifact_from_path(bad)[0].parsed
    assert (
        detect_artifact_type(
            ROOT / "fake_graphql_inventory.json",
            json.loads((ROOT / "fake_graphql_inventory.json").read_text()),
        )
        == ArtifactType.GRAPHQL_INVENTORY
    )


def test_asset_signal_lead_scoring_and_reports():
    value = project()
    user = next(x for x in value.assets if x.normalized_path == "/api/users/{id}")
    assert (
        user.related_endpoints
        and user.related_authz_findings
        and user.related_evidence_workspaces
    )
    gql = next(x for x in value.assets if x.path == "/graphql")
    assert gql.related_graphql_operations
    types = {x.signal_type for x in value.signals}
    assert {
        "idor-candidate",
        "authz-mismatch",
        "object-id-variable",
        "evidence-ready",
    } <= types
    assert score([x for x in value.signals if x.asset_id == user.id]) >= 70
    assert any(
        x.reportability == Reportability.REPORT_READY for x in value.triage_leads
    )
    assert any(
        x.reportability == Reportability.LIKELY_NOISE for x in value.triage_leads
    )
    assert "Project Correlation Report" in render_markdown(value)
    assert "Highest-priority leads" in render_checklist(value)
    assert "Project triage leads" in render_leads(value)
    exported = render_json(value)
    assert "synthetic-secret-value" not in exported
    json.loads(exported)


def test_round_trip_and_cli(tmp_path):
    path = tmp_path / "project.yml"
    save(project(), path)
    assert load_project(path).artifacts
    runner = CliRunner()
    for args in [
        ["correlate", "--help"],
        ["correlate", "assets", str(path)],
        ["correlate", "signals", str(path)],
        ["correlate", "leads", str(path)],
        ["correlate", "report", str(path), "--format", "json"],
        ["correlate", "export-leads", str(path), "--format", "markdown"],
        ["correlate", "checklist", str(path), "--format", "json"],
        ["correlate", "build", str(path)],
    ]:
        result = runner.invoke(app, args)
        assert result.exit_code == 0, result.output
    added = runner.invoke(
        app,
        [
            "correlate",
            "add-artifact",
            str(path),
            str(ROOT / "fake_endpoint_inventory.json"),
            "--type",
            "endpoint_inventory",
        ],
    )
    assert added.exit_code == 0
    scanned = runner.invoke(
        app,
        [
            "correlate",
            "scan",
            str(ROOT / "fake_project_folder"),
            "--output",
            str(tmp_path / "scan.yml"),
        ],
    )
    assert scanned.exit_code == 0
