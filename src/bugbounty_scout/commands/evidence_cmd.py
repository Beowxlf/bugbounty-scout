"""Evidence Locker CLI commands."""

from pathlib import Path

import typer
from rich.console import Console

from bugbounty_scout.models import EvidenceType
from bugbounty_scout.modules.evidence_locker import (
    add_file,
    add_note,
    add_step,
    load_workspace,
    new_workspace,
    render_json,
    render_markdown,
    save_workspace,
    set_severity,
    slugify,
)
from bugbounty_scout.modules.report_quality import lint_workspace

app = typer.Typer(help="Organize local, redacted evidence without sending requests.")
console = Console()


def _load(path: Path):
    try:
        return load_workspace(path)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from None


def _save(workspace, path: Path) -> None:
    try:
        save_workspace(workspace, path)
    except (ValueError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from None


@app.command("init")
def init(title: str) -> None:
    output = Path(f"{slugify(title)}-evidence.yml")
    if output.exists():
        console.print(
            f"[red]Error:[/red] Refusing to overwrite existing file: {output}"
        )
        raise typer.Exit(2)
    _save(new_workspace(title), output)
    console.print(f"[green]Created evidence workspace:[/green] {output}")


@app.command("add-note")
def note(
    workspace_file: Path, title: str = typer.Option(...), text: str = typer.Option(...)
) -> None:
    workspace = _load(workspace_file)
    item = add_note(workspace, title, text)
    _save(workspace, workspace_file)
    typer.echo(item.id)


def _attach(workspace_file: Path, file: Path, kind: str, title: str) -> None:
    workspace = _load(workspace_file)
    try:
        item = add_file(workspace, file, kind, title=title)
    except (ValueError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from None
    _save(workspace, workspace_file)
    typer.echo(item.id)


@app.command("add-request")
def request(
    workspace_file: Path,
    request_file: Path,
    title: str = typer.Option("Request evidence"),
) -> None:
    _attach(workspace_file, request_file, "raw_request", title)


@app.command("add-response")
def response(
    workspace_file: Path,
    response_file: Path,
    title: str = typer.Option("Response evidence"),
) -> None:
    _attach(workspace_file, response_file, "raw_response", title)


@app.command("add-screenshot")
def screenshot(
    workspace_file: Path, image_file: Path, title: str = typer.Option("Screenshot")
) -> None:
    _attach(workspace_file, image_file, "screenshot", title)


@app.command("add-file")
def arbitrary_file(
    workspace_file: Path,
    file: Path,
    type: EvidenceType = typer.Option(..., "--type"),
    title: str = typer.Option(""),
) -> None:
    _attach(workspace_file, file, type.value, title)


@app.command("add-step")
def step(
    workspace_file: Path,
    action: str = typer.Option(...),
    expected: str = typer.Option(...),
    actual: str = typer.Option(...),
    evidence: str = typer.Option(""),
) -> None:
    workspace = _load(workspace_file)
    item = add_step(workspace, action, expected, actual, evidence)
    _save(workspace, workspace_file)
    typer.echo(item.id)


@app.command("set-impact")
def impact(workspace_file: Path, impact: str = typer.Option(...)) -> None:
    workspace = _load(workspace_file)
    workspace.impact = impact
    _save(workspace, workspace_file)


@app.command("set-behavior")
def behavior(
    workspace_file: Path,
    expected: str = typer.Option(...),
    actual: str = typer.Option(...),
) -> None:
    workspace = _load(workspace_file)
    workspace.expected_behavior, workspace.actual_behavior = expected, actual
    _save(workspace, workspace_file)


@app.command("set-severity")
def severity(
    workspace_file: Path,
    severity: str = typer.Option(...),
    rationale: str = typer.Option(...),
) -> None:
    workspace = _load(workspace_file)
    try:
        set_severity(workspace, severity, rationale)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None
    _save(workspace, workspace_file)


@app.command("list")
def list_items(workspace_file: Path) -> None:
    workspace = _load(workspace_file)
    for item in workspace.evidence_items:
        typer.echo(f"{item.id}\t{item.type.value}\t{item.title}\t{item.sha256}")


@app.command("lint")
def lint(workspace_file: Path) -> None:
    workspace = _load(workspace_file)
    warnings = lint_workspace(workspace)
    _save(workspace, workspace_file)
    for warning in warnings:
        typer.echo(
            f"{warning.severity.value}: {warning.category.value}: {warning.message}"
        )


@app.command("export")
def export(
    workspace_file: Path, format: str = typer.Option("markdown", "--format")
) -> None:
    workspace = _load(workspace_file)
    lint_workspace(workspace)
    value = format.lower()
    if value not in {"markdown", "json"}:
        raise typer.BadParameter("must be 'markdown' or 'json'")
    typer.echo(
        render_markdown(workspace) if value == "markdown" else render_json(workspace)
    )
