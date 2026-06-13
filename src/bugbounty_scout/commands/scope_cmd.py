"""ScopeGuard CLI commands."""

from pathlib import Path

import typer
from rich.console import Console

from bugbounty_scout.config import dump_yaml
from bugbounty_scout.scope import check_scope, load_scope, scope_template

app = typer.Typer(help="Create and evaluate offline scope policies.")
console = Console()


@app.command("init")
def init_scope(
    output: Path = typer.Option(Path("scope.yml"), "--output", "-o"),
) -> None:
    """Create a safe scope configuration template."""
    if output.exists():
        console.print(
            f"[red]Error:[/red] Refusing to overwrite existing file: {output}"
        )
        raise typer.Exit(2)
    try:
        dump_yaml(scope_template(), output)
    except OSError as exc:
        console.print(f"[red]Error:[/red] Could not write scope template: {exc}")
        raise typer.Exit(2) from None
    console.print(f"[green]Created scope template:[/green] {output}")


@app.command("check")
def check(
    url: str,
    scope_file: Path = typer.Option(Path("scope.yml"), "--scope-file", "-s"),
) -> None:
    """Check a URL without making a network request."""
    try:
        decision = check_scope(url, load_scope(scope_file))
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    color = "green" if decision.allowed else "red"
    label = "ALLOWED" if decision.allowed else "DENIED"
    console.print(f"[{color}]{label}[/{color}]: {decision.reason}")
    if decision.matched_rule:
        console.print(f"Matched rule: {decision.matched_rule}")
    if not decision.allowed:
        raise typer.Exit(1)
