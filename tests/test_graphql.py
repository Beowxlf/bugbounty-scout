from pathlib import Path

import pytest
from typer.testing import CliRunner

from bugbounty_scout.cli import app
from bugbounty_scout.modules.graphql_mapper import (
    render_checklist,
    render_json,
    render_markdown,
    scan_file,
    scan_folder,
)

F = Path("fixtures/graphql")


def test_har_endpoint_operations_variables_leads_and_redaction():
    inv = scan_file(F / "fake_graphql.har")
    assert inv.endpoints and inv.endpoints[0].path == "/graphql"
    assert {x.operation_type.value for x in inv.operations} >= {"query", "mutation"}
    assert {x.name for x in inv.variables} >= {"userId", "tenantId", "fileId", "orgId"}
    assert any(x.object_id_candidate for x in inv.variables)
    assert {x.category.value for x in inv.review_leads} >= {
        "idor_bola_candidate",
        "state_changing_mutation",
        "sensitive_field_exposure",
        "excessive_error_detail",
    }
    assert "fake-token" not in render_json(
        inv
    ) and "fake@example.test" not in render_json(inv)


def test_graphql_js_fragments_schema_introspection_batch_and_folder():
    query = scan_file(F / "fake_query.graphql")
    assert query.fragments and "email" in query.fragments[0].fields
    assert scan_file(F / "fake_frontend_graphql.js").endpoints
    schema = scan_file(F / "fake_schema.graphql").schema_artifacts[0]
    assert (
        "updateUserRole" in schema.mutation_names
        and "accountChanged" in schema.subscription_names
    )
    intro = scan_file(F / "fake_introspection.json")
    assert intro.schema_artifacts[0].artifact_type.value == "introspection_json"
    assert any(
        x.category.value == "batching_indicator"
        for x in scan_file(F / "fake_batched_request.har").review_leads
    )
    assert len(scan_folder(F / "fake_folder").source_files) == 2


def test_inventory_evidence_errors_reports_and_checklist(tmp_path):
    assert scan_file(F / "fake_endpoint_inventory.json").endpoints
    assert scan_file(F / "fake_frontend_inventory.json").endpoints
    assert scan_file(F / "fake_auth_surface_inventory.json").endpoints
    assert scan_file(F / "fake_evidence_workspace.yml").operations
    inv = scan_file(F / "fake_graphql.har")
    md = render_markdown(inv)
    check = render_checklist(inv)
    for heading in (
        "Summary",
        "Sources analyzed",
        "GraphQL endpoints",
        "Operations inventory",
        "Variables and object-ID candidates",
        "Sensitive fields",
        "Fragments",
        "Schema/introspection artifacts",
        "Review leads",
        "Manual testing checklist",
        "Redaction notice",
        "Limitations",
    ):
        assert f"## {heading}" in md
    assert "## Object ID / BOLA review" in check
    bad = tmp_path / "bad.json"
    bad.write_text("{")
    with pytest.raises(ValueError, match="Invalid JSON"):
        scan_file(bad)
    har = tmp_path / "bad.har"
    har.write_text("{}")
    with pytest.raises(ValueError, match="log.entries"):
        scan_file(har)
    malformed = tmp_path / "bad.graphql"
    malformed.write_text("query Broken($id: ID! {")
    assert scan_file(malformed).operations == []


def test_cli_workflows():
    runner = CliRunner()
    commands = [
        ["graphql", "scan-har", str(F / "fake_graphql.har")],
        ["graphql", "scan-file", str(F / "fake_query.graphql")],
        ["graphql", "scan-folder", str(F / "fake_folder")],
        ["graphql", "scan-inventory", str(F / "fake_endpoint_inventory.json")],
        ["graphql", "endpoints", str(F / "fake_graphql.har")],
        ["graphql", "operations", str(F / "fake_graphql.har")],
        ["graphql", "variables", str(F / "fake_graphql.har")],
        ["graphql", "schema", str(F / "fake_introspection.json")],
        ["graphql", "leads", str(F / "fake_graphql.har")],
        ["graphql", "report", str(F / "fake_graphql.har"), "--format", "markdown"],
        ["graphql", "report", str(F / "fake_graphql.har"), "--format", "json"],
        ["graphql", "checklist", str(F / "fake_graphql.har"), "--format", "json"],
    ]
    for command in commands:
        result = runner.invoke(app, command)
        assert result.exit_code == 0, result.output
