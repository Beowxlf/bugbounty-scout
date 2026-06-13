import json
from pathlib import Path

import pytest

from bugbounty_scout.har import (
    analyze_cache,
    analyze_cookies,
    analyze_har,
    analyze_headers,
    analyze_third_parties,
    detect_sensitive_material,
    extract_endpoints,
    parse_har,
    render_json,
    render_markdown,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_parse_har_summary() -> None:
    summary = parse_har(FIXTURES / "fake.har")
    assert summary.entry_count == 3
    assert summary.methods == {"GET": 2, "POST": 1}
    assert summary.status_codes == {"200": 1, "201": 1, "204": 1}
    assert summary.entries[0].request_headers["Accept"] == "application/json"


def test_endpoint_extraction_normalizes_and_extracts_query_names() -> None:
    endpoints = extract_endpoints(FIXTURES / "fake.har")
    assert len(endpoints) == 3
    profile = next(item for item in endpoints if item.path == "/api/profile")
    assert profile.host == "example.test"
    assert profile.query_parameters == ["view"]
    assert profile.status_codes == [200]


def test_sensitive_detection_reports_locations_without_values() -> None:
    findings = detect_sensitive_material(FIXTURES / "fake.har")
    categories = {item.category for item in findings}
    locations = {item.location for item in findings}
    assert {"bearer_token", "jwt", "api_key", "email", "phone_number"} <= categories
    assert {
        "request header",
        "query parameter",
        "request body",
        "response body",
    } <= locations
    serialized = json.dumps([item.model_dump() for item in findings])
    assert "fake-bearer-token-value" not in serialized
    assert "fake-api-key-value" not in serialized


def test_cookie_parsing_and_missing_attribute_observations() -> None:
    cookies = analyze_cookies(FIXTURES / "cookies_missing_attributes.har")
    session = next(item for item in cookies if item.name == "session_id")
    assert session.cookie_type == "session"
    assert not session.secure
    assert not session.http_only
    assert any("SameSite" in note for note in session.observations)


def test_header_review_is_conservative() -> None:
    headers = analyze_headers(FIXTURES / "fake.har")
    wildcard = next(
        item
        for item in headers
        if item.header == "access-control-allow-origin" and item.value == "*"
    )
    assert wildcard.classification == "needs manual review"
    missing = [item for item in headers if item.value == "<missing>"]
    assert all(item.classification == "informational" for item in missing)


def test_third_party_host_and_sensitive_category_detection() -> None:
    third_parties = analyze_third_parties(FIXTURES / "third_party_email.har")
    assert len(third_parties) == 1
    assert third_parties[0].host == "analytics.vendor.test"
    assert "email" in third_parties[0].sensitive_categories
    assert "fake@example.test" not in json.dumps(third_parties[0].model_dump())


def test_risky_cache_is_manual_review() -> None:
    reviews = analyze_cache(FIXTURES / "risky_cache.har")
    assert len(reviews) == 1
    assert reviews[0].classification == "needs manual review"
    assert "public" in reviews[0].observation.lower()


def test_malformed_and_empty_har_handling(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="log.entries list"):
        parse_har(FIXTURES / "malformed.har")
    empty = tmp_path / "empty.har"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        parse_har(empty)


def test_markdown_and_json_reports_are_redacted() -> None:
    analysis = analyze_har(FIXTURES / "fake.har")
    markdown = render_markdown(analysis)
    json_report = render_json(analysis)
    assert "## Endpoint inventory" in markdown
    assert "## Manual follow-up checklist" in markdown
    assert "fake-bearer-token-value" not in markdown
    assert "researcher@example.test" not in markdown
    assert "fake-api-key-value" not in json_report
    assert json.loads(json_report)["primary_host"] == "example.test"
    assert analysis.findings[0].location
