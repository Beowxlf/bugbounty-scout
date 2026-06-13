from bugbounty_scout.models import ScopeProfile
from bugbounty_scout.scope import check_scope


def profile() -> ScopeProfile:
    return ScopeProfile(
        program_name="Synthetic",
        in_scope=["example.test", "*.api.example.test"],
        out_of_scope=["admin.example.test", "example.test/private/*"],
    )


def test_exact_domain_allowed() -> None:
    decision = check_scope("https://example.test/public", profile())
    assert decision.allowed
    assert decision.matched_rule == "example.test"


def test_wildcard_subdomain_allowed_but_not_apex() -> None:
    assert check_scope("https://v1.api.example.test/data", profile()).allowed
    wildcard_only = ScopeProfile(program_name="Synthetic", in_scope=["*.example.test"])
    assert not check_scope("https://example.test", wildcard_only).allowed


def test_explicit_domain_and_path_exclusions_win() -> None:
    assert not check_scope("https://admin.example.test", profile()).allowed
    decision = check_scope("https://example.test/private/users", profile())
    assert not decision.allowed
    assert decision.matched_rule == "example.test/private/*"


def test_invalid_and_unmatched_urls_denied() -> None:
    assert not check_scope("example.test", profile()).allowed
    assert not check_scope("https://other.test", profile()).allowed
