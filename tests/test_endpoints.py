import json
from pathlib import Path

import pytest

from bugbounty_scout.modules.endpoints import (
    inventory_from_file,
    inventory_from_folder,
    normalize_path,
)
from bugbounty_scout.modules.passive_api import (
    generate_checklist,
    render_checklist_json,
    render_checklist_markdown,
    render_inventory_json,
    render_inventory_markdown,
)

FIXTURES = Path(__file__).parent.parent / "fixtures" / "endpoints"


def test_har_endpoint_parameters_auth_and_tags() -> None:
    inventory = inventory_from_file(FIXTURES / "simple_api.har")
    user = next(item for item in inventory.endpoints if item.path == "/api/users/123")
    invoice = next(item for item in inventory.endpoints if "invoices" in item.path)
    upload = next(item for item in inventory.endpoints if "upload" in item.path)
    assert user.normalized_path == "/api/users/{id}"
    assert user.query_params == ["include"]
    assert "userId" in user.json_keys
    assert "bearer token" in user.auth_indicators
    assert {"invoiceId", "accountId"} <= set(invoice.json_keys)
    assert {"cookie auth", "CSRF token"} <= set(invoice.auth_indicators)
    assert {"billing", "idor-candidate", "state-changing"} <= set(invoice.risk_tags)
    assert {"file", "projectId"} <= set(upload.body_params)


def test_normalization_preserves_assets() -> None:
    assert normalize_path("/api/users/123") == "/api/users/{id}"
    assert (
        normalize_path("/api/users/550e8400-e29b-41d4-a716-446655440000")
        == "/api/users/{uuid}"
    )
    assert (
        normalize_path("/api/orgs/acme-corp/invoices/98765")
        == "/api/orgs/{slug}/invoices/{id}"
    )
    assert normalize_path("/static/app.123.js") == "/static/app.123.js"


def test_js_html_json_text_and_folder_extraction() -> None:
    js = inventory_from_file(FIXTURES / "fake_frontend.js")
    assert any(
        item.method == "POST" and "admin" in item.risk_tags for item in js.endpoints
    )
    assert any("graphql" in item.risk_tags for item in js.endpoints)
    assert any("websocket" in item.risk_tags for item in js.endpoints)
    html = inventory_from_file(FIXTURES / "fake_app.html")
    login = next(item for item in html.endpoints if item.path == "/auth/login")
    assert {"email", "password", "csrfToken"} <= set(login.body_params)
    assert any(
        item.path == "/admin/users"
        for item in inventory_from_file(FIXTURES / "fake_config.json").endpoints
    )
    folder = inventory_from_folder(FIXTURES / "fake_folder")
    assert len(folder.source_files) == 2
    assert any(
        item.normalized_path.endswith("/documents/{uuid}") for item in folder.endpoints
    )


def test_reports_checklists_and_redaction() -> None:
    inventory = inventory_from_file(FIXTURES / "simple_api.har")
    markdown = render_inventory_markdown(inventory)
    structured = json.loads(render_inventory_json(inventory))
    for heading in (
        "Summary",
        "Hosts observed",
        "Endpoint inventory",
        "High-interest endpoints",
        "Auth indicators",
        "Object ID candidates",
        "Risk tags",
        "Parameters observed",
        "Source files",
        "Manual review notes",
        "Redaction notice",
        "Limitations",
    ):
        assert f"## {heading}" in markdown
    assert "fake-redacted-value" not in markdown
    assert "fake-session" not in json.dumps(structured)
    items = generate_checklist(inventory)
    assert any(item.category == "idor-candidate" for item in items)
    assert "Can User A access" in render_checklist_markdown(items)
    assert json.loads(render_checklist_json(items))


def test_malformed_empty_and_unsupported_files(tmp_path: Path) -> None:
    malformed = tmp_path / "bad.har"
    malformed.write_text("{", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid HAR"):
        inventory_from_file(malformed)
    empty = tmp_path / "empty.txt"
    empty.write_text("", encoding="utf-8")
    assert inventory_from_file(empty).endpoints == []
    unsupported = tmp_path / "input.xml"
    unsupported.write_text("<x/>", encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported"):
        inventory_from_file(unsupported)
