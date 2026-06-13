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
        console.print(f"[red]Error:[/red] File does not exist: {file}")
        raise typer.Exit(2)
    destination = output or file.with_name(f"{file.name}.redacted")
    try:
        text = file.read_text(encoding="utf-8")
        if not text:
            raise ValueError(f"Input file is empty: {file}")
        destination.write_text(redact_text(text), encoding="utf-8")
    except (OSError, ValueError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from None
    console.print(f"[green]Wrote redacted file:[/green] {destination}")
