import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from bugbounty_scout.cli import app
from bugbounty_scout.modules.paramforge import (
    export_all,
    export_wordlist,
    normalize_term,
    render_json,
    render_markdown,
    risk_score,
    safe_mutations,
    scan_file,
    scan_folder,
    select_terms,
    tags_for,
)

FIXTURES = Path("fixtures/paramforge")
runner = CliRunner()


def values(inventory, category=None):
    return {
        term.normalized_value
        for term in inventory.terms
        if category is None or term.category.value == category
    }


def test_har_extracts_request_response_graphql_and_names_only():
    inventory = scan_file(FIXTURES / "fake_api.har")
    assert {"includedetails", "userid"} <= values(inventory, "query_param")
    assert "paymentmethodid" in values(inventory, "billing_term")
    assert "errorcode" in values(inventory, "response_key")
    assert "authorization" in values(inventory, "header_name")
    assert "sessionid" in values(inventory, "cookie_name")
    assert "updateaccount" in values(inventory, "graphql_operation")
    assert "accountid" in values(inventory, "graphql_variable")
    exported = export_wordlist(inventory, "all", "txt")
    assert "fake-secret-value" not in exported
    assert "pm_fake" not in exported


@pytest.mark.parametrize(
    ("file", "expected"),
    [
        ("fake_frontend.js", "activeaccountid"),
        ("fake_app.html", "emailaddress"),
        ("fake_config.json", "apibasepath"),
        ("fake_graphql.json", "invitemember"),
    ],
)
def test_file_types(file, expected):
    assert expected in values(scan_file(FIXTURES / file))


def test_folder_scan_and_frequency_scoring():
    inventory = scan_folder(FIXTURES / "fake_folder")
    assert "accountid" in values(inventory)
    assert "upload" in values(inventory)
    assert all(term.frequency_score >= 1 for term in inventory.terms)


@pytest.mark.parametrize(
    ("file", "expected"),
    [
        ("fake_endpoint_inventory.json", "permissionname"),
        ("fake_frontend_inventory.json", "activetenantid"),
        ("fake_authz_matrix.yml", "organization_admin"),
        ("fake_evidence_workspace.yml", "invoiceid"),
    ],
)
def test_inventory_sources(file, expected):
    assert expected in values(scan_file(FIXTURES / file))


def test_normalization_stopwords_mutations_risk_and_tags():
    assert normalize_term(" 'User%49d' ") == "userid"
    inventory = scan_file(FIXTURES / "fake_frontend.js")
    assert "const" not in values(inventory)
    mutations = safe_mutations("paymentMethod")
    assert {"payment_method", "payment-method", "paymentMethods"} <= set(mutations)
    assert risk_score("adminBillingExport") > risk_score("buttonLabel")
    assert {"admin", "billing", "export"} <= set(tags_for("adminBillingExport"))


def test_reports_and_exports(tmp_path):
    inventory = scan_file(FIXTURES / "fake_api.har")
    markdown = render_markdown(inventory)
    assert "## Top terms by frequency" in markdown
    assert "## Redaction notice" in markdown
    assert json.loads(render_json(inventory))["terms"]
    assert "term,category" in export_wordlist(inventory, "params", "csv")
    assert (
        json.loads(export_wordlist(inventory, "params", "json"))["category"] == "params"
    )
    assert select_terms(inventory, "params")
    outputs = export_all(inventory, tmp_path)
    assert len(outputs) == 14
    assert (tmp_path / "all_terms.txt").is_file()


def test_empty_malformed_and_unsupported(tmp_path):
    empty = tmp_path / "empty.txt"
    empty.write_text("")
    assert scan_file(empty).terms == []
    malformed = tmp_path / "bad.json"
    malformed.write_text("{")
    with pytest.raises(ValueError, match="Invalid structured file"):
        scan_file(malformed)
    unsupported = tmp_path / "image.png"
    unsupported.write_text("not an image")
    with pytest.raises(ValueError, match="Unsupported"):
        scan_file(unsupported)


def test_cli_workflows(tmp_path):
    result = runner.invoke(
        app, ["paramforge", "scan-har", str(FIXTURES / "fake_api.har")]
    )
    assert result.exit_code == 0
    assert "query_param" in result.stdout
    result = runner.invoke(
        app,
        [
            "paramforge",
            "report",
            str(FIXTURES / "fake_endpoint_inventory.json"),
            "--format",
            "markdown",
        ],
    )
    assert result.exit_code == 0
    assert "ParamForge Passive Vocabulary Report" in result.stdout
    result = runner.invoke(
        app,
        [
            "paramforge",
            "export-all",
            str(FIXTURES / "fake_endpoint_inventory.json"),
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    assert (tmp_path / "params.txt").exists()
