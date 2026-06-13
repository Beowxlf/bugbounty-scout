import pytest
from pydantic import ValidationError

from bugbounty_scout.models import ApiInventory, Endpoint, Finding


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
    assert finding.location == ""


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


def test_endpoint_inventory_models_have_safe_defaults() -> None:
    endpoint = Endpoint(
        id="ep-test", path="/api/users/123", normalized_path="/api/users/{id}"
    )
    inventory = ApiInventory(endpoints=[endpoint])
    assert endpoint.method == "UNKNOWN"
    assert endpoint.created_at.tzinfo is not None
    assert inventory.generated_at.tzinfo is not None
