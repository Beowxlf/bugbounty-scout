"""Redaction CLI command."""

from pathlib import Path

import typer
from rich.console import Console

from bugbounty_scout.redaction import redact_text

console = Console()


def redact_file(
    file: Path,
    output: Path | None = typer.Option(None, "--output", "-o"),
) -> None:
    """Create a redacted copy of a local text file."""
    if not file.is_file():
        raise typer.BadParameter(f"File does not exist: {file}")
    destination = output or file.with_name(f"{file.name}.redacted")
    try:
        text = file.read_text(encoding="utf-8")
        destination.write_text(redact_text(text), encoding="utf-8")
    except OSError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    console.print(f"[green]Wrote redacted file:[/green] {destination}")
