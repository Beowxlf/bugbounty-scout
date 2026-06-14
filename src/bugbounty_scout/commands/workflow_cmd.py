"""Workflow Orchestrator commands."""

import json
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.table import Table

from bugbounty_scout.modules.workflow import (
    clean,
    detect,
    initialize_workspace,
    load_manifest,
    render_report,
    render_summary,
    run,
)

app = typer.Typer(help="Orchestrate existing passive modules over local files.")
console = Console()


def _format(value: str, allowed: set[str]) -> str:
    value = value.lower()
    if value not in allowed:
        raise typer.BadParameter(f"must be one of: {', '.join(sorted(allowed))}")
    return value


def _load(root: Path):
    try:
        return load_manifest(root.resolve())
    except (ValueError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc


@app.command("init")
def init(project_name: Path) -> None:
    """Create a marked local workflow workspace."""
    try:
        initialize_workspace(project_name)
    except (ValueError, FileExistsError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    console.print(
        f"[green]Created workflow workspace:[/green] {project_name.resolve()}"
    )
    console.print("Local files only; no live requests or request replay.")


@app.command("detect")
def detect_inputs(workspace_or_input_folder: Path) -> None:
    """Classify local inputs and update workflow.yml."""
    try:
        manifest, _ = detect(workspace_or_input_folder)
    except (ValueError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    table = Table(title="Detected workflow inputs")
    for column in ("Path", "Type", "Size", "Modules", "Parse status"):
        table.add_column(column)
    for item in manifest.inputs:
        table.add_row(
            item.path,
            item.input_type.value,
            str(item.size_bytes),
            ", ".join(item.detected_modules) or "none",
            item.parse_status,
        )
    console.print(table)
    console.print(f"Detected {len(manifest.inputs)} local input(s).")


@app.command("run")
def run_workflow(workspace_folder: Path) -> None:
    """Run the safe local passive pipeline and continue after isolated failures."""
    try:
        manifest = run(workspace_folder)
    except (ValueError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    for step in manifest.steps:
        console.print(f"{step.name}: {step.status.value}")
    console.print(f"[green]Workflow complete:[/green] {workspace_folder.resolve()}")


@app.command("status")
def status(workspace_folder: Path) -> None:
    """Show manifest counts, reports, warnings, and last update time."""
    manifest = _load(workspace_folder)
    summary = manifest.summary
    table = Table(title=f"Workflow status: {manifest.project_name}")
    table.add_column("Field")
    table.add_column("Value")
    values = (
        ("Workspace", manifest.workspace_path),
        ("Inputs", str(len(manifest.inputs))),
        ("Completed steps", str(summary.completed_steps)),
        ("Skipped steps", str(summary.skipped_steps)),
        ("Failed steps", str(summary.failed_steps)),
        ("Outputs", str(len(manifest.outputs))),
        ("Updated", manifest.updated_at.isoformat()),
        (
            "Reports",
            ", ".join(
                item.path
                for item in manifest.outputs
                if item.path.startswith("reports/")
            )
            or "none",
        ),
        ("Warnings", "; ".join(summary.warnings) or "none"),
    )
    for key, value in values:
        table.add_row(key, value)
    console.print(table)


@app.command("summary")
def summary(
    workspace_folder: Path,
    format: str = typer.Option("markdown", "--format"),
) -> None:
    """Print the project summary as Markdown or JSON."""
    typer.echo(
        render_summary(_load(workspace_folder), _format(format, {"markdown", "json"}))
    )


@app.command("report")
def report(
    workspace_folder: Path,
    format: str = typer.Option("markdown", "--format"),
) -> None:
    """Print a concise project report referencing module artifacts."""
    typer.echo(
        render_report(_load(workspace_folder), _format(format, {"markdown", "json"}))
    )


@app.command("manifest")
def manifest(
    workspace_folder: Path,
    format: str = typer.Option("yaml", "--format"),
) -> None:
    """Export workflow.yml for auditability and repeatability."""
    data = _load(workspace_folder).model_dump(mode="json")
    value = _format(format, {"yaml", "json"})
    typer.echo(
        yaml.safe_dump(data, sort_keys=False)
        if value == "yaml"
        else json.dumps(data, indent=2)
    )


@app.command("clean")
def clean_workspace(
    workspace_folder: Path,
    outputs_only: bool = typer.Option(False, "--outputs-only"),
) -> None:
    """Safely remove outputs, or the complete marked workflow workspace."""
    try:
        clean(workspace_folder, outputs_only)
    except (ValueError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    action = "Reset outputs for" if outputs_only else "Removed"
    console.print(f"[green]{action} workflow workspace:[/green] {workspace_folder}")
