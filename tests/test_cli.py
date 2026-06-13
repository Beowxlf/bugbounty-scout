from typer.testing import CliRunner

from bugbounty_scout.cli import app


def test_cli_import_and_help() -> None:
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "BugBountyScout" in result.output


def test_har_malformed_error_has_no_traceback() -> None:
    result = CliRunner().invoke(app, ["har", "summary", "fixtures/malformed.har"])
    assert result.exit_code == 2
    assert "Error:" in result.output
    assert "Traceback" not in result.output
