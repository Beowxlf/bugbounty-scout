"""Passive Endpoint Mapper CLI commands."""

from pathlib import Path

import typer
from rich.console import Console

from bugbounty_scout.modules.endpoints import (
    inventory_from_file,
    inventory_from_folder,
    load_inventory,
)
from bugbounty_scout.modules.passive_api import (
    generate_checklist,
    render_checklist_json,
    render_checklist_markdown,
    render_inventory_json,
    render_inventory_markdown,
)

app = typer.Typer(
    help="Map endpoints passively from local captures and frontend files."
)
console = Console()


def _run(path: Path, folder: bool = False):
    try:
        return inventory_from_folder(path) if folder else inventory_from_file(path)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from None


@app.command("from-har")
def from_har(har_file: Path) -> None:
    """Extract a JSON endpoint inventory from a local HAR."""
    typer.echo(render_inventory_json(_run(har_file)))


@app.command("from-file")
def from_file(file: Path) -> None:
    """Extract a JSON endpoint inventory from a supported local file."""
    typer.echo(render_inventory_json(_run(file)))


@app.command("from-folder")
def from_folder(folder: Path) -> None:
    """Extract a JSON endpoint inventory from supported files in a folder."""
    typer.echo(render_inventory_json(_run(folder, folder=True)))


def _format(value: str) -> str:
    value = value.lower()
    if value not in {"markdown", "json"}:
        raise typer.BadParameter("must be 'markdown' or 'json'")
    return value


@app.command("report")
def report(input: Path, format: str = typer.Option("markdown", "--format")) -> None:
    """Generate a passive endpoint inventory report."""
    try:
        inventory = load_inventory(input)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from None
    typer.echo(
        render_inventory_markdown(inventory)
        if _format(format) == "markdown"
        else render_inventory_json(inventory)
    )


@app.command("checklist")
def checklist(input: Path, format: str = typer.Option("markdown", "--format")) -> None:
    """Generate tag-driven manual testing questions without payloads."""
    try:
        items = generate_checklist(load_inventory(input))
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from None
    typer.echo(
        render_checklist_markdown(items)
        if _format(format) == "markdown"
        else render_checklist_json(items)
    )
