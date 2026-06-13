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


def test_endpoints_cli_commands() -> None:
    source = "fixtures/endpoints/fake_frontend.js"
    result = CliRunner().invoke(app, ["endpoints", "from-file", source])
    assert result.exit_code == 0
    assert '"endpoints"' in result.output
    report = CliRunner().invoke(
        app, ["endpoints", "report", source, "--format", "markdown"]
    )
    assert report.exit_code == 0
    assert "## Endpoint inventory" in report.output
