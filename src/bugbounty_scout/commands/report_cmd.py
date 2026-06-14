"""Report CLI commands."""

from pathlib import Path

import typer
from rich.console import Console

from bugbounty_scout.modules.evidence_locker import (
    load_workspace,
)
from bugbounty_scout.modules.evidence_locker import (
    render_json as render_evidence_json,
)
from bugbounty_scout.modules.evidence_locker import (
    render_markdown as render_evidence_markdown,
)
from bugbounty_scout.modules.report_quality import lint_workspace
from bugbounty_scout.reporting import export_markdown, finding_warnings, load_finding

app = typer.Typer(help="Export redacted finding reports.")
console = Console()


@app.command("export")
def export(
    finding_file: Path,
    format: str = typer.Option("markdown", "--format"),
    output: Path | None = typer.Option(None, "--output", "-o"),
) -> None:
    """Export a finding or evidence workspace as redacted Markdown/JSON."""
    try:
        data = __import__("bugbounty_scout.config", fromlist=["load_data"]).load_data(
            finding_file
        )
        if isinstance(data, dict) and "evidence_items" in data:
            workspace = load_workspace(finding_file)
            lint_workspace(workspace)
            value = format.lower()
            if value not in {"markdown", "json"}:
                raise ValueError("--format must be 'markdown' or 'json'")
            content = (
                render_evidence_markdown(workspace)
                if value == "markdown"
                else render_evidence_json(workspace)
            )
            if output:
                output.write_text(content + "\n", encoding="utf-8")
                console.print(f"[green]Exported report:[/green] {output}")
            else:
                typer.echo(content)
            return
        finding = load_finding(finding_file)
        destination = output or finding_file.with_suffix(".md")
        export_markdown(finding, destination)
    except (ValueError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from None
    for warning in finding_warnings(finding):
        console.print(f"[yellow]Warning:[/yellow] {warning}")
    console.print(f"[green]Exported report:[/green] {destination}")


@app.command("lint")
def lint(report_file: Path) -> None:
    """Lint an evidence workspace or legacy finding without blocking export."""
    try:
        data = __import__("bugbounty_scout.config", fromlist=["load_data"]).load_data(
            report_file
        )
        if isinstance(data, dict) and "evidence_items" in data:
            for warning in lint_workspace(load_workspace(report_file)):
                typer.echo(
                    f"{warning.severity.value}: {warning.category.value}: "
                    f"{warning.message}"
                )
        else:
            for warning in finding_warnings(load_finding(report_file)):
                typer.echo(f"low: legacy_finding: {warning}")
    except (ValueError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from None
