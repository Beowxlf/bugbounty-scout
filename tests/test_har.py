from pathlib import Path

from bugbounty_scout.har import parse_har

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_parse_har_summary() -> None:
    summary = parse_har(FIXTURES / "fake.har")
    assert summary.entry_count == 2
    assert summary.methods == {"GET": 1, "POST": 1}
    assert summary.status_codes == {"200": 1, "201": 1}
    assert summary.mime_types == {"application/json": 2}
    assert summary.entries[0].request_headers["Accept"] == "application/json"
