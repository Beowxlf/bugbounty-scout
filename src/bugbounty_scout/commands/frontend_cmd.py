"""Frontend Exposure Analyzer CLI commands."""

import json
from pathlib import Path

import typer
from rich.console import Console

from bugbounty_scout.modules.frontend import scan_file, scan_folder, scan_input
from bugbounty_scout.modules.frontend_reporting import render_json, render_markdown

app = typer.Typer(help="Passively analyze local frontend files and source maps.")
console = Console()


def _run(path: Path, mode: str = "input"):
    try:
        return {"file": scan_file, "folder": scan_folder}.get(mode, scan_input)(path)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from None


@app.command("scan-file")
def scan_file_command(file: Path) -> None:
    """Scan one supported local frontend file."""
    typer.echo(render_json(_run(file, "file")))


@app.command("scan-folder")
def scan_folder_command(folder: Path) -> None:
    """Scan supported files beneath a local folder."""
    typer.echo(render_json(_run(folder, "folder")))


def _subset(input: Path, field: str) -> None:
    value = getattr(_run(input), field)
    typer.echo(json.dumps([item.model_dump(mode="json") for item in value], indent=2))


@app.command("secrets")
def secrets(input: Path) -> None:
    """List redacted secret and identifier observations."""
    _subset(input, "secrets")


@app.command("sourcemaps")
def sourcemaps(input: Path) -> None:
    """List local source-map references and parsed observations."""
    _subset(input, "source_maps")


@app.command("storage")
def storage(input: Path) -> None:
    """List client-side storage review leads."""
    _subset(input, "storage_references")


@app.command("dom-leads")
def dom_leads(input: Path) -> None:
    """List source/sink proximity leads without generating payloads."""
    _subset(input, "dom_review_leads")


@app.command("postmessage")
def postmessage(input: Path) -> None:
    """List postMessage review leads."""
    _subset(input, "postmessage_leads")


@app.command("report")
def report(input: Path, format: str = typer.Option("markdown", "--format")) -> None:
    """Generate a redacted Markdown or JSON frontend report."""
    value = format.lower()
    if value not in {"markdown", "json"}:
        raise typer.BadParameter("must be 'markdown' or 'json'")
    inventory = _run(input)
    typer.echo(
        render_markdown(inventory) if value == "markdown" else render_json(inventory)
    )
