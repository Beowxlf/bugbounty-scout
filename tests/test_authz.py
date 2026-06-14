import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from bugbounty_scout.cli import app
from bugbounty_scout.modules.authz_matrix import (
    add_actor,
    add_endpoint,
    add_expectation,
    add_object,
    compare,
    generate_checklist,
    generate_findings,
    import_endpoints,
    load_matrix,
    new_matrix,
    record_result,
    render_json,
    render_markdown,
    save_matrix,
)

FIXTURES = Path("fixtures/authz")


def test_matrix_initialization_and_round_trip(tmp_path: Path) -> None:
    matrix = new_matrix("Synthetic authz")
    path = tmp_path / "matrix.yml"
    save_matrix(matrix, path)
    loaded = load_matrix(path)
    assert loaded.project_name == "Synthetic authz"
    assert loaded.actors == []
    assert "does not send" in loaded.summary["safety_notice"]


def test_actor_object_endpoint_expectation_and_observation() -> None:
    matrix = new_matrix("Unit test")
    owner = add_actor(matrix, "User A", "user", organization="Org A")
    other = add_actor(matrix, "User B", "user", organization="Org B")
    obj = add_object(
        matrix,
        "invoice",
        "Invoice A",
        owner.id,
        {"invoiceId": "inv_123"},
        sensitivity="high",
    )
    endpoint = add_endpoint(
        matrix, "GET", "/api/invoices/{invoiceId}", ["idor-candidate", "billing"]
    )
    rule = add_expectation(
        matrix, other.id, obj.id, endpoint.id, "deny", "Different owner", "user"
    )
    observed = record_result(
        matrix,
        other.id,
        obj.id,
        endpoint.id,
        "allowed",
        status_code=200,
        evidence_reference="evidence/redacted-response.txt",
    )
    assert rule.expected_result.value == "deny"
    assert observed.observed_result.value == "allowed"
    assert compare(matrix)[0]["mismatch"]
    finding = generate_findings(matrix)[0]
    assert finding.finding_type.value == "idor"
    assert finding.severity.value == "high"
    assert finding.confidence.value == "high"


def test_import_only_high_interest_endpoints() -> None:
    matrix = new_matrix("Import")
    imported = import_endpoints(matrix, FIXTURES / "fake_endpoint_inventory.json")
    assert imported
    assert all(
        set(item.risk_tags) & {"idor-candidate", "admin", "billing", "state-changing"}
        for item in imported
    )
    assert not any(".js" in item.path_template for item in imported)


def test_severity_boundary_and_state_change() -> None:
    matrix = load_matrix(FIXTURES / "fake_authz_matrix.yml")
    findings = generate_findings(matrix)
    by_type = {item.finding_type.value: item for item in findings}
    assert by_type["cross_org_access"].severity.value == "high"
    assert by_type["state_changing_authz_failure"].severity.value == "high"
    assert any(item.severity.value == "info" for item in findings)


def test_checklist_and_reports_are_complete_and_redacted() -> None:
    matrix = load_matrix(FIXTURES / "fake_authz_matrix.yml")
    checklist = generate_checklist(matrix)
    assert {item["category"] for item in checklist} >= {
        "user",
        "organization",
        "tenant",
        "state-changing",
        "admin",
    }
    markdown = render_markdown(matrix)
    structured = json.loads(render_json(matrix))
    for heading in (
        "Summary",
        "Actors",
        "Objects",
        "Endpoint templates",
        "Expected access matrix",
        "Observed access matrix",
        "Mismatches",
        "Candidate findings",
        "Evidence references",
        "Manual follow-up checklist",
        "Redaction notice",
        "Limitations",
    ):
        assert f"## {heading}" in markdown
    assert "fake-sensitive-token" not in markdown
    assert "fake@example.test" not in json.dumps(structured)
    assert structured["findings"]


def test_identifier_and_report_redaction() -> None:
    matrix = new_matrix("Redaction")
    actor = add_actor(matrix, "User", "user")
    obj = add_object(
        matrix,
        "user",
        "Profile",
        actor.id,
        {"email": "fake@example.test", "api_key": "fake-sensitive-token"},
    )
    assert obj.identifiers["email"] == "<redacted-email>"
    assert "fake-sensitive-token" not in render_json(matrix)


def test_malformed_and_missing_reference_validation(tmp_path: Path) -> None:
    malformed = tmp_path / "bad.yml"
    malformed.write_text("actors: [", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid authorization matrix"):
        load_matrix(malformed)
    matrix = new_matrix("Validation")
    with pytest.raises(ValueError, match="Unknown actor"):
        add_object(matrix, "invoice", "Invoice", "actor-missing")
    actor = add_actor(matrix, "User", "user")
    with pytest.raises(ValueError, match="Unknown object"):
        add_expectation(matrix, actor.id, "missing", "missing", "deny", "test")


def test_authz_cli_flow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(app, ["authz", "init", "demo"])
    assert result.exit_code == 0
    matrix_file = tmp_path / "demo-authz-matrix.yml"
    actor = runner.invoke(
        app,
        ["authz", "add-actor", str(matrix_file), "--name", "User A", "--role", "user"],
    )
    assert actor.exit_code == 0
    actor_id = actor.output.strip()
    obj = runner.invoke(
        app,
        [
            "authz",
            "add-object",
            str(matrix_file),
            "--type",
            "invoice",
            "--name",
            "Invoice A",
            "--owner",
            actor_id,
        ],
    )
    assert obj.exit_code == 0
    endpoint = runner.invoke(
        app,
        [
            "authz",
            "add-endpoint",
            str(matrix_file),
            "--method",
            "GET",
            "--path",
            "/api/invoices/{invoiceId}",
        ],
    )
    assert endpoint.exit_code == 0
    report = runner.invoke(
        app, ["authz", "report", str(matrix_file), "--format", "markdown"]
    )
    assert report.exit_code == 0
    assert "IDOR/BOLA Matrix" in report.output
