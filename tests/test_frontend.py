import json
from pathlib import Path

import pytest

from bugbounty_scout.modules.frontend import scan_file, scan_folder
from bugbounty_scout.modules.frontend_reporting import render_json, render_markdown

FIXTURES = Path("fixtures/frontend")


def test_js_secret_config_public_identifier_and_routes() -> None:
    inventory = scan_file(FIXTURES / "fake_frontend.js")
    types = {item.type for item in inventory.secrets}
    assert {"jwt", "bearer-token", "api-key", "stripe-publishable-key"} <= types
    stripe = next(
        item for item in inventory.secrets if item.type == "stripe-publishable-key"
    )
    assert stripe.context["classification"] == "public identifier"
    assert stripe.severity.value == "info"
    assert any("admin" in route.risk_tags for route in inventory.routes)
    assert "fake-bearer-token-value" not in render_json(inventory)


def test_html_json_runtime_and_folder_scans() -> None:
    assert scan_file(FIXTURES / "fake_app.html").runtime_configs
    config = scan_file(FIXTURES / "fake_config.json")
    assert any(item.type == "api-key" for item in config.secrets)
    folder = scan_folder(FIXTURES / "fake_folder")
    assert len(folder.source_files) == 7
    assert folder.runtime_configs and folder.storage_references
    assert folder.dom_review_leads and folder.postmessage_leads


def test_source_map_reference_parse_embedded_source_and_comments() -> None:
    bundle = scan_file(FIXTURES / "fake_bundle_with_sourcemap.js")
    assert any(
        item.finding_type == "source-map-reference" for item in bundle.source_maps
    )
    source_map = scan_file(FIXTURES / "fake_bundle_with_sourcemap.js.map")
    types = {item.finding_type for item in source_map.source_maps}
    assert {"source-map-exposure", "sensitive-comment"} <= types
    assert any(route.path == "/api/billing/export" for route in source_map.routes)


def test_storage_dom_postmessage_and_reports() -> None:
    assert len(scan_file(FIXTURES / "fake_storage.js").storage_references) >= 4
    assert scan_file(FIXTURES / "fake_dom_review.js").dom_review_leads
    leads = scan_file(FIXTURES / "fake_postmessage.js").postmessage_leads
    assert any(not item.has_origin_check for item in leads)
    inventory = scan_folder(FIXTURES / "fake_folder")
    markdown = render_markdown(inventory)
    structured = json.loads(render_json(inventory))
    for heading in (
        "Summary",
        "Files analyzed",
        "Frontend secret/config findings",
        "Runtime config observations",
        "Source map observations",
        "Routes and API client hints",
        "Client storage review leads",
        "DOM review leads",
        "postMessage review leads",
        "Manual follow-up checklist",
        "Redaction notice",
        "Limitations",
    ):
        assert f"## {heading}" in markdown
    assert structured["summary"]["files_analyzed"] == 7
    assert "fake-api-key-value-12345" not in markdown


def test_empty_malformed_and_unsupported(tmp_path: Path) -> None:
    empty = tmp_path / "empty.js"
    empty.write_text("", encoding="utf-8")
    assert scan_file(empty).findings == []
    malformed = tmp_path / "bad.map"
    malformed.write_text("{", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid source map JSON"):
        scan_file(malformed)
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid JSON"):
        scan_file(bad_json)
    unsupported = tmp_path / "file.xml"
    unsupported.write_text("<x/>", encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported"):
        scan_file(unsupported)
