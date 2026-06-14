"""BugBountyScout command-line interface."""

from pathlib import Path

import typer
from rich.console import Console

from bugbounty_scout import __version__
from bugbounty_scout.commands import (
    auth_surface_cmd,
    authz_cmd,
    correlate_cmd,
    demo_cmd,
    doctor_cmd,
    endpoints_cmd,
    evidence_cmd,
    frontend_cmd,
    graphql_cmd,
    har_cmd,
    paramforge_cmd,
    report_cmd,
    scope_cmd,
)
from bugbounty_scout.commands.redact_cmd import redact_file
from bugbounty_scout.workspace import create_workspace

app = typer.Typer(
    name="bbs",
    help="BugBountyScout: local-first workbench for authorized web bug bounty testing.",
    no_args_is_help=True,
)
app.add_typer(scope_cmd.app, name="scope")
app.add_typer(report_cmd.app, name="report")
app.add_typer(har_cmd.app, name="har")
app.add_typer(endpoints_cmd.app, name="endpoints")
app.add_typer(frontend_cmd.app, name="frontend")
app.add_typer(authz_cmd.app, name="authz")
app.add_typer(auth_surface_cmd.app, name="auth-surface")
app.add_typer(evidence_cmd.app, name="evidence")
app.add_typer(paramforge_cmd.app, name="paramforge")
app.add_typer(graphql_cmd.app, name="graphql")
app.add_typer(correlate_cmd.app, name="correlate")
app.add_typer(demo_cmd.app, name="demo")
app.command("redact")(redact_file)
app.command("doctor")(doctor_cmd.doctor)
console = Console()


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"bbs {__version__}")
        raise typer.Exit


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """Run BugBountyScout locally and only on authorized targets."""


@app.command()
def init(workspace_name: str) -> None:
    """Create a new local workspace."""
    try:
        root = create_workspace(workspace_name, Path.cwd())
    except (ValueError, FileExistsError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    console.print(f"[green]Created workspace:[/green] {root}")
    console.print("Authorized use only. Review scope before testing.")


if __name__ == "__main__":
    app()
