import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from bugbounty_scout.cli import app
from bugbounty_scout.modules.auth_surface import (
    decode_jwt,
    render_checklist,
    render_json,
    render_markdown,
    scan_file,
    scan_folder,
)

F = Path("fixtures/auth_surface")


def test_jwt_decode_lifetime_claims_and_redaction():
    token = F.joinpath("fake_jwt.txt").read_text().split()[-1]
    item = decode_jwt(token, "fake", "text")
    assert item and item.algorithm == "HS256" and item.lifetime_seconds > 86400
    assert {"admin-like-role", "sensitive-claims", "tenant-claims"} <= set(
        item.risk_tags
    )
    assert token not in item.model_dump_json() and not decode_jwt("bad.jwt.value")


def test_har_cookie_headers_cors_cache_endpoints_and_reports():
    inv = scan_file(F / "fake_auth.har")
    session = next(c for c in inv.cookie_observations if c.name == "session_id")
    assert session.cookie_type == "session" and {
        "missing-secure",
        "missing-httponly",
        "missing-samesite",
    } <= set(session.risk_tags)
    assert any(
        "csp-unsafe-inline" in x.risk_tags for x in inv.security_header_observations
    )
    assert any(
        "wildcard-with-credentials" in x.risk_tags for x in inv.cors_observations
    )
    assert inv.cache_observations and {
        "login",
        "oauth",
        "callback",
        "password-reset",
    } <= {t for e in inv.auth_endpoints for t in e.risk_tags}
    md = render_markdown(inv)
    data = json.loads(render_json(inv))
    check = render_checklist(inv)
    assert all(
        "## " + x in md
        for x in [
            "Summary",
            "JWT observations",
            "Cookie observations",
            "Security header observations",
            "CORS observations",
            "Cache observations",
            "Redaction notice",
            "Limitations",
        ]
    )
    assert data["jwt_observations"] and "fake-signature" not in render_json(inv)
    assert "## JWT review" in check and "## Tenant/org auth review" in check


def test_raw_folder_inventory_evidence_and_errors(tmp_path):
    assert scan_file(F / "fake_response.txt").cookie_observations
    assert scan_file(F / "fake_endpoint_inventory.json").auth_endpoints
    assert scan_file(F / "fake_evidence_workspace.yml").jwt_observations
    assert len(scan_folder(F / "fake_folder").source_files) == 2
    bad = tmp_path / "bad.har"
    bad.write_text("{")
    with pytest.raises(ValueError, match="Invalid JSON"):
        scan_file(bad)
    malformed = tmp_path / "malformed.har"
    malformed.write_text("{}")
    with pytest.raises(ValueError, match="log.entries"):
        scan_file(malformed)


def test_cli_workflows():
    runner = CliRunner()
    for args in [
        ["auth-surface", "scan-har", str(F / "fake_auth.har")],
        ["auth-surface", "scan-file", str(F / "fake_jwt.txt")],
        ["auth-surface", "scan-folder", str(F / "fake_folder")],
        ["auth-surface", "scan-inventory", str(F / "fake_endpoint_inventory.json")],
        ["auth-surface", "jwt", str(F / "fake_jwt.txt")],
        ["auth-surface", "cookies", str(F / "fake_auth.har")],
        ["auth-surface", "headers", str(F / "fake_headers_response.txt")],
        ["auth-surface", "cors", str(F / "fake_cors.har")],
        ["auth-surface", "cache", str(F / "fake_cache.har")],
        ["auth-surface", "report", str(F / "fake_auth.har"), "--format", "markdown"],
        ["auth-surface", "report", str(F / "fake_auth.har"), "--format", "json"],
        ["auth-surface", "checklist", str(F / "fake_auth.har"), "--format", "json"],
    ]:
        result = runner.invoke(app, args)
        assert result.exit_code == 0, result.output
