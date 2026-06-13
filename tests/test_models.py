import pytest
from pydantic import ValidationError

from bugbounty_scout.models import Finding


def test_valid_finding() -> None:
    finding = Finding(
        id="BBS-001",
        title="Synthetic cache metadata",
        type="information-disclosure",
        severity="low",
        confidence="high",
        asset="https://example.test",
        source_module="manual",
    )
    assert finding.severity.value == "low"
    assert finding.created_at.tzinfo is not None


def test_finding_rejects_invalid_severity_and_blank_title() -> None:
    with pytest.raises(ValidationError):
        Finding(
            id="BBS-001",
            title=" ",
            type="test",
            severity="urgent",
            confidence="high",
            asset="https://example.test",
            source_module="manual",
        )
