"""HAR summary CLI commands."""

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from bugbounty_scout.har import parse_har

app = typer.Typer(help="Summarize passive HAR captures.")
console = Console()


@app.command("summary")
def summary(
    har_file: Path,
    json_output: bool = typer.Option(False, "--json", help="Print JSON output."),
) -> None:
    """Summarize HAR entries without making requests or scanning secrets."""
    try:
        result = parse_har(har_file)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    if json_output:
        typer.echo(json.dumps(result.model_dump(), indent=2))
        return

    table = Table(title=f"HAR summary ({result.entry_count} entries)")
    for heading in ("Method", "URL", "Status", "MIME type"):
        table.add_column(heading)
    for entry in result.entries:
        table.add_row(entry.method, entry.url, str(entry.status), entry.mime_type)
    console.print(table)
