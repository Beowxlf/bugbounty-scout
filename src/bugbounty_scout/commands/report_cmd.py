"""Report CLI commands."""

from pathlib import Path

import typer
from rich.console import Console

from bugbounty_scout.reporting import export_markdown, finding_warnings, load_finding

app = typer.Typer(help="Export redacted finding reports.")
console = Console()


@app.command("export")
def export(
    finding_file: Path,
    output: Path | None = typer.Option(None, "--output", "-o"),
) -> None:
    """Export a YAML or JSON finding as redacted Markdown."""
    try:
        finding = load_finding(finding_file)
        destination = output or finding_file.with_suffix(".md")
        export_markdown(finding, destination)
    except (ValueError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from None
    for warning in finding_warnings(finding):
        console.print(f"[yellow]Warning:[/yellow] {warning}")
    console.print(f"[green]Exported report:[/green] {destination}")
