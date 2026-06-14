"""Project Correlator CLI commands."""

from pathlib import Path

import typer
from rich.console import Console

from bugbounty_scout.models import ArtifactType
from bugbounty_scout.modules.correlator import (
    artifact_from_path,
    load_project,
    render_checklist,
    render_json,
    render_leads,
    render_markdown,
    save,
)
from bugbounty_scout.modules.correlator import (
    build as build_project,
)
from bugbounty_scout.modules.correlator import (
    scan as scan_folder,
)

app = typer.Typer(help="Correlate local module outputs into conservative triage leads.")
console = Console()


def _load(path: Path):
    try:
        return load_project(path)
    except (ValueError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc


def _format(value: str) -> str:
    if value not in {"markdown", "json"}:
        raise typer.BadParameter("must be 'markdown' or 'json'")
    return value


@app.command("scan")
def scan(
    folder: Path,
    output: Path = typer.Option(Path("correlation-project.yml"), "--output", "-o"),
):
    try:
        path = scan_folder(folder, output)
    except (ValueError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    typer.echo(str(path))


@app.command("add-artifact")
def add_artifact(
    project_file: Path,
    artifact_file: Path,
    type: ArtifactType = typer.Option(..., "--type"),
):
    project = _load(project_file)
    try:
        artifact, _ = artifact_from_path(artifact_file, type.value)
        project.artifacts = [
            x for x in project.artifacts if x.sha256 != artifact.sha256
        ]
        project.artifacts.append(artifact)
        save(project, project_file)
    except (ValueError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    typer.echo(artifact.id)


@app.command("build")
def build(project_file: Path):
    project = build_project(_load(project_file))
    save(project, project_file)
    typer.echo(render_json(project))


@app.command("assets")
def assets(project_file: Path):
    import json

    typer.echo(
        json.dumps(
            [x.model_dump(mode="json") for x in _load(project_file).assets], indent=2
        )
    )


@app.command("signals")
def signals(project_file: Path):
    import json

    typer.echo(
        json.dumps(
            [x.model_dump(mode="json") for x in _load(project_file).signals], indent=2
        )
    )


@app.command("leads")
def leads(project_file: Path):
    typer.echo(render_leads(_load(project_file), "json"))


@app.command("report")
def report(project_file: Path, format: str = typer.Option("markdown", "--format")):
    project = _load(project_file)
    typer.echo(
        render_markdown(project)
        if _format(format) == "markdown"
        else render_json(project)
    )


@app.command("export-leads")
def export_leads(
    project_file: Path, format: str = typer.Option("markdown", "--format")
):
    typer.echo(render_leads(_load(project_file), _format(format)))


@app.command("checklist")
def checklist(project_file: Path, format: str = typer.Option("markdown", "--format")):
    typer.echo(render_checklist(_load(project_file), _format(format)))
