import json
import tomllib
from pathlib import Path

import yaml
from typer.testing import CliRunner

from bugbounty_scout.cli import app
from bugbounty_scout.commands.doctor_cmd import collect_checks
from bugbounty_scout.har import analyze_har
from bugbounty_scout.models import ProjectCorrelationInventory
from bugbounty_scout.modules.auth_surface import scan_file as scan_auth
from bugbounty_scout.modules.authz_matrix import generate_findings, load_matrix
from bugbounty_scout.modules.correlator import (
    artifact_from_path,
    build,
    discover,
)
from bugbounty_scout.modules.endpoints import inventory_from_file
from bugbounty_scout.modules.evidence_locker import load_workspace, render_markdown
from bugbounty_scout.modules.frontend import scan_file as scan_frontend
from bugbounty_scout.modules.graphql_mapper import scan_file as scan_graphql
from bugbounty_scout.modules.paramforge import scan_file as scan_vocabulary

ROOT = Path(__file__).parent.parent


def test_doctor_table_json_and_registration() -> None:
    runner = CliRunner()
    help_result = runner.invoke(app, ["--help"])
    assert help_result.exit_code == 0
    for command in ("doctor", "demo", "har", "endpoints", "correlate"):
        assert command in help_result.output
    table = runner.invoke(app, ["doctor"])
    assert table.exit_code == 0
    assert "Redaction sanity" in table.output
    assert "No network requests were made" in table.output
    structured = runner.invoke(app, ["doctor", "--format", "json"])
    assert structured.exit_code == 0
    data = json.loads(structured.output)
    assert data["redaction_sanity"] and data["json_yaml_sanity"]
    assert data["network_requests"] is False
    assert set(data["runtime_imports"]) == {"typer", "pydantic", "yaml", "rich"}
    assert collect_checks()["bugbounty_scout_version"]


def test_demo_lifecycle_and_safety(tmp_path: Path) -> None:
    runner = CliRunner()
    demo = tmp_path / "safe-demo"
    created = runner.invoke(app, ["demo", "init", str(demo)])
    assert created.exit_code == 0, created.output
    assert "Synthetic local files only" in created.output
    expected = {
        "inputs/fake.har",
        "inputs/fake_frontend.js",
        "inputs/fake_graphql.har",
        "inputs/fake_request.txt",
        "inputs/fake_response.txt",
        "outputs",
        "evidence",
        "reports",
        "README.md",
        "workflow.md",
        "scope.yml",
    }
    assert all(demo.joinpath(item).exists() for item in expected)
    json.loads(demo.joinpath("inputs/fake.har").read_text())
    json.loads(demo.joinpath("inputs/fake_graphql.har").read_text())
    scope = yaml.safe_load(demo.joinpath("scope.yml").read_text())
    assert scope["in_scope"] == ["api.example.test"]
    workflow = demo.joinpath("workflow.md").read_text()
    assert "bbs correlate scan outputs/" in workflow
    assert "not automatically executed" in workflow
    assert "real secrets" in workflow
    status = runner.invoke(app, ["demo", "status", str(demo)])
    assert status.exit_code == 0
    cleaned = runner.invoke(app, ["demo", "clean", str(demo)])
    assert cleaned.exit_code == 0
    assert not demo.exists()


def test_packaging_metadata_and_release_assets() -> None:
    data = tomllib.loads(ROOT.joinpath("pyproject.toml").read_text())
    project = data["project"]
    assert project["name"] == "bugbounty-scout"
    assert project["requires-python"] == ">=3.11"
    assert project["scripts"]["bbs"] == "bugbounty_scout.cli:app"
    dependencies = " ".join(project["dependencies"]).lower()
    assert all(name in dependencies for name in ("typer", "pydantic", "pyyaml", "rich"))
    dev = " ".join(project["optional-dependencies"]["dev"]).lower()
    assert "pytest" in dev and "ruff" in dev
    assert data["build-system"]["build-backend"] == "hatchling.build"
    assert data["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == [
        "src/bugbounty_scout"
    ]
    for relative in (
        "CHANGELOG.md",
        "docs/command-reference.md",
        "docs/release-checklist.md",
        "docs/example-workflow.md",
        "scripts/test_bench_validation.sh",
        "scripts/test_bench_validation.ps1",
        "scripts/smoke_py_path.sh",
    ):
        assert ROOT.joinpath(relative).is_file()


def test_fixture_only_end_to_end_workflow() -> None:
    har_report = analyze_har(ROOT / "fixtures/fake.har")
    assert har_report.summary.entry_count

    endpoints = inventory_from_file(ROOT / "fixtures/endpoints/simple_api.har")
    assert any(endpoint.risk_tags for endpoint in endpoints.endpoints)

    frontend = scan_frontend(ROOT / "fixtures/frontend/fake_frontend.js")
    assert frontend.findings and frontend.routes

    auth = scan_auth(ROOT / "fixtures/auth_surface/fake_auth.har")
    assert auth.cookie_observations and auth.auth_endpoints

    graphql = scan_graphql(ROOT / "fixtures/graphql/fake_graphql.har")
    assert graphql.operations and graphql.review_leads

    vocabulary = scan_vocabulary(ROOT / "fixtures/paramforge/fake_api.har")
    assert vocabulary.terms and vocabulary.categories

    matrix = load_matrix(ROOT / "fixtures/authz/fake_authz_matrix.yml")
    assert generate_findings(matrix)

    evidence = load_workspace(ROOT / "fixtures/evidence/fake_workspace.yml")
    assert "## Evidence items" in render_markdown(evidence)

    folder = ROOT / "fixtures/correlate/fake_project_folder"
    artifacts = [artifact_from_path(path)[0] for path in discover(folder)]
    correlated = build(
        ProjectCorrelationInventory(
            project_name="Phase 3A fixture workflow", artifacts=artifacts
        )
    )
    assert correlated.triage_leads and correlated.signals
