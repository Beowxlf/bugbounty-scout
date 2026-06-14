"""GraphQL Risk Mapper commands."""

import json
from pathlib import Path

import typer
from rich.console import Console

from bugbounty_scout.modules.graphql_mapper import (
    load_or_scan,
    render_checklist,
    render_json,
    render_markdown,
    scan_file,
    scan_folder,
)

app = typer.Typer(help="Passively map GraphQL risk signals from local artifacts.")
console = Console()


def _load(path: Path):
    try:
        return load_or_scan(path)
    except (ValueError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc


def _scan(path: Path, folder: bool = False):
    try:
        return scan_folder(path) if folder else scan_file(path)
    except (ValueError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc


def _dump(items):
    typer.echo(json.dumps([x.model_dump(mode="json") for x in items], indent=2))


@app.command("scan-har")
def scan_har(har_file: Path):
    typer.echo(render_json(_scan(har_file)))


@app.command("scan-file")
def scan_local_file(file: Path):
    typer.echo(render_json(_scan(file)))


@app.command("scan-folder")
def scan_local_folder(folder: Path):
    typer.echo(render_json(_scan(folder, True)))


@app.command("scan-inventory")
def scan_inventory(inventory_file: Path):
    typer.echo(render_json(_scan(inventory_file)))


@app.command("endpoints")
def endpoints(input: Path):
    _dump(_load(input).endpoints)


@app.command("operations")
def operations(input: Path):
    _dump(_load(input).operations)


@app.command("variables")
def variables(input: Path):
    _dump(_load(input).variables)


@app.command("schema")
def schema(input: Path):
    _dump(_load(input).schema_artifacts)


@app.command("leads")
def leads(input: Path):
    _dump(_load(input).review_leads)


@app.command("report")
def report(input: Path, format: str = typer.Option("markdown", "--format")):
    inv = _load(input)
    if format == "markdown":
        typer.echo(render_markdown(inv))
    elif format == "json":
        typer.echo(render_json(inv))
    else:
        raise typer.BadParameter("must be 'markdown' or 'json'")


@app.command("checklist")
def checklist(input: Path, format: str = typer.Option("markdown", "--format")):
    try:
        typer.echo(render_checklist(_load(input), format))
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
