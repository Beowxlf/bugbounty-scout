"""IDOR/BOLA Matrix CLI commands."""

import json
from pathlib import Path

import typer
from rich.console import Console

from bugbounty_scout.modules.authz_matrix import (
    add_actor,
    add_endpoint,
    add_expectation,
    add_object,
    compare,
    generate_findings,
    import_endpoints,
    load_matrix,
    new_matrix,
    record_result,
    render_checklist_json,
    render_checklist_markdown,
    render_json,
    render_markdown,
    save_matrix,
)

app = typer.Typer(help="Organize manual IDOR/BOLA authorization testing.")
console = Console()


def _load(path: Path):
    try:
        return load_matrix(path)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from None


def _save(matrix, path: Path) -> None:
    try:
        save_matrix(matrix, path)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from None


@app.command("init")
def init_matrix(project_name: str) -> None:
    """Create an empty local YAML authorization matrix."""
    output = Path(f"{project_name}-authz-matrix.yml")
    if output.exists():
        console.print(
            f"[red]Error:[/red] Refusing to overwrite existing file: {output}"
        )
        raise typer.Exit(2)
    _save(new_matrix(project_name), output)
    console.print(f"[green]Created authorization matrix:[/green] {output}")


@app.command("add-actor")
def actor(
    matrix_file: Path,
    name: str = typer.Option(..., "--name"),
    role: str = typer.Option(..., "--role"),
    organization: str = typer.Option("", "--organization"),
    tenant: str = typer.Option("", "--tenant"),
    account_type: str = typer.Option("", "--account-type"),
) -> None:
    matrix = _load(matrix_file)
    item = add_actor(
        matrix,
        name,
        role,
        organization=organization,
        tenant=tenant,
        account_type=account_type,
    )
    _save(matrix, matrix_file)
    typer.echo(item.id)


def _identifiers(values: list[str]) -> dict[str, str]:
    result = {}
    for value in values:
        if "=" not in value:
            raise typer.BadParameter("identifier must use key=value")
        key, item = value.split("=", 1)
        result[key] = item
    return result


@app.command("add-object")
def object_command(
    matrix_file: Path,
    object_type: str = typer.Option(..., "--type"),
    name: str = typer.Option(..., "--name"),
    owner: str = typer.Option(..., "--owner"),
    organization: str = typer.Option("", "--organization"),
    tenant: str = typer.Option("", "--tenant"),
    identifier: list[str] = typer.Option(None, "--identifier"),
) -> None:
    matrix = _load(matrix_file)
    try:
        item = add_object(
            matrix,
            object_type,
            name,
            owner,
            _identifiers(identifier or []),
            organization=organization,
            tenant=tenant,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None
    _save(matrix, matrix_file)
    typer.echo(item.id)


@app.command("add-endpoint")
def endpoint(
    matrix_file: Path,
    method: str = typer.Option(..., "--method"),
    path: str = typer.Option(..., "--path"),
    tag: list[str] = typer.Option(None, "--tag"),
) -> None:
    matrix = _load(matrix_file)
    item = add_endpoint(matrix, method, path, tag or [])
    _save(matrix, matrix_file)
    typer.echo(item.id)


@app.command("import-endpoints")
def import_command(matrix_file: Path, endpoint_inventory_json: Path) -> None:
    matrix = _load(matrix_file)
    try:
        imported = import_endpoints(matrix, endpoint_inventory_json)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from None
    _save(matrix, matrix_file)
    typer.echo(f"Imported {len(imported)} endpoint template(s).")


@app.command("expect")
def expect(
    matrix_file: Path,
    actor: str = typer.Option(..., "--actor"),
    object_id: str = typer.Option(..., "--object"),
    endpoint: str = typer.Option(..., "--endpoint"),
    result: str = typer.Option(..., "--result"),
    reason: str = typer.Option(..., "--reason"),
    boundary: str = typer.Option("unknown", "--boundary"),
) -> None:
    matrix = _load(matrix_file)
    try:
        item = add_expectation(
            matrix, actor, object_id, endpoint, result, reason, boundary
        )
    except (ValueError, TypeError) as exc:
        raise typer.BadParameter(str(exc)) from None
    _save(matrix, matrix_file)
    typer.echo(item.id)


@app.command("record")
def record(
    matrix_file: Path,
    actor: str = typer.Option(..., "--actor"),
    object_id: str = typer.Option(..., "--object"),
    endpoint: str = typer.Option(..., "--endpoint"),
    result: str = typer.Option(..., "--result"),
    status_code: int | None = typer.Option(None, "--status-code"),
    response_length: int | None = typer.Option(None, "--response-length"),
    content_hash: str = typer.Option("", "--content-hash"),
    key_field: list[str] = typer.Option(None, "--key-field"),
    data_changed: bool | None = typer.Option(None, "--data-changed/--no-data-changed"),
    error_message: str = typer.Option("", "--error-message"),
    evidence: str = typer.Option("", "--evidence"),
    notes: str = typer.Option("", "--notes"),
) -> None:
    matrix = _load(matrix_file)
    try:
        item = record_result(
            matrix,
            actor,
            object_id,
            endpoint,
            result,
            status_code=status_code,
            response_length=response_length,
            content_hash=content_hash,
            key_fields_visible=key_field or [],
            data_changed=data_changed,
            error_message=error_message,
            evidence_reference=evidence,
            notes=notes,
        )
    except (ValueError, TypeError) as exc:
        raise typer.BadParameter(str(exc)) from None
    _save(matrix, matrix_file)
    typer.echo(item.id)


@app.command("compare")
def compare_command(matrix_file: Path) -> None:
    typer.echo(json.dumps(compare(_load(matrix_file)), indent=2))


@app.command("findings")
def findings(matrix_file: Path) -> None:
    matrix = _load(matrix_file)
    items = generate_findings(matrix)
    _save(matrix, matrix_file)
    typer.echo(json.dumps([item.model_dump(mode="json") for item in items], indent=2))


def _format(value: str) -> str:
    if value.lower() not in {"markdown", "json"}:
        raise typer.BadParameter("must be 'markdown' or 'json'")
    return value.lower()


@app.command("report")
def report(
    matrix_file: Path, format: str = typer.Option("markdown", "--format")
) -> None:
    matrix = _load(matrix_file)
    typer.echo(
        render_markdown(matrix)
        if _format(format) == "markdown"
        else render_json(matrix)
    )


@app.command("checklist")
def checklist(
    matrix_file: Path, format: str = typer.Option("markdown", "--format")
) -> None:
    matrix = _load(matrix_file)
    typer.echo(
        render_checklist_markdown(matrix)
        if _format(format) == "markdown"
        else render_checklist_json(matrix)
    )
