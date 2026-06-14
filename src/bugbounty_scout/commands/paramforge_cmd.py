"""ParamForge passive vocabulary builder commands."""

from pathlib import Path

import typer
from rich.console import Console

from bugbounty_scout.modules.paramforge import (
    export_all,
    export_wordlist,
    load_or_scan,
    render_json,
    render_markdown,
    scan_file,
    scan_folder,
)

app = typer.Typer(help="Build redacted, target-specific vocabulary from local inputs.")
console = Console()


def _print_inventory(path: Path, *, folder: bool = False) -> None:
    try:
        inventory = scan_folder(path) if folder else scan_file(path)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    typer.echo(render_json(inventory))


@app.command("scan-har")
def scan_har(har_file: Path) -> None:
    """Extract vocabulary from a local HAR without sending requests."""
    if har_file.suffix.lower() != ".har":
        console.print("[red]Error:[/red] scan-har requires a .har file")
        raise typer.Exit(2)
    _print_inventory(har_file)


@app.command("scan-file")
def scan_local_file(file: Path) -> None:
    """Extract vocabulary from one supported local file."""
    _print_inventory(file)


@app.command("scan-folder")
def scan_local_folder(folder: Path) -> None:
    """Recursively extract vocabulary from supported local files."""
    _print_inventory(folder, folder=True)


@app.command("scan-inventory")
def scan_inventory(inventory_file: Path) -> None:
    """Extract vocabulary from a local module inventory or workspace."""
    _print_inventory(inventory_file)


@app.command("report")
def report(
    input: Path,
    format: str = typer.Option("markdown", "--format", help="markdown or json"),
) -> None:
    """Render a ParamForge report from a local input or saved inventory."""
    try:
        inventory = load_or_scan(input)
        if format == "markdown":
            typer.echo(render_markdown(inventory))
        elif format == "json":
            typer.echo(render_json(inventory))
        else:
            raise ValueError("Report format must be markdown or json")
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc


@app.command("export")
def export(
    input: Path,
    category: str = typer.Option(..., "--category"),
    format: str = typer.Option("txt", "--format", help="txt, csv, or json"),
) -> None:
    """Write a safe names-only wordlist to standard output."""
    try:
        typer.echo(export_wordlist(load_or_scan(input), category, format), nl=False)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc


@app.command("export-all")
def export_everything(
    input: Path,
    output_dir: Path = typer.Option(..., "--output-dir"),
) -> None:
    """Write the standard names-only wordlist set."""
    try:
        paths = export_all(load_or_scan(input), output_dir)
    except (ValueError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    for path in paths:
        typer.echo(path)


@app.command("stats")
def stats(input: Path) -> None:
    """Show concise vocabulary counts and safety status."""
    try:
        inventory = load_or_scan(input)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    typer.echo(f"Sources analyzed: {len(inventory.source_files)}")
    typer.echo(f"Unique categorized terms: {len(inventory.terms)}")
    typer.echo(f"Occurrences: {inventory.summary.get('occurrences', 0)}")
    for category, count in inventory.categories.items():
        typer.echo(f"{category}: {count}")
    typer.echo("Mode: passive/local-only; exports contain names, not secret values.")
