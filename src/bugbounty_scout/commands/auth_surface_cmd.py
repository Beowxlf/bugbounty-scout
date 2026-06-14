"""Auth Surface Analyzer commands."""

from pathlib import Path

import typer
from rich.console import Console

from bugbounty_scout.modules.auth_surface import (
    load_or_scan,
    render_checklist,
    render_json,
    render_markdown,
    scan_file,
    scan_folder,
)

app = typer.Typer(help="Passively review auth/session signals in local artifacts.")
console = Console()


def _run(path: Path, folder: bool = False, kind: str = "all") -> None:
    try:
        inv = scan_folder(path) if folder else scan_file(path)
    except (ValueError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    if kind == "all":
        typer.echo(render_json(inv))
        return
    fields = {
        "jwt": "jwt_observations",
        "cookies": "cookie_observations",
        "headers": "security_header_observations",
        "cors": "cors_observations",
        "cache": "cache_observations",
    }
    import json

    typer.echo(
        json.dumps(
            [x.model_dump(mode="json") for x in getattr(inv, fields[kind])], indent=2
        )
    )


@app.command("scan-har")
def scan_har(har_file: Path) -> None:
    _run(har_file)


@app.command("scan-file")
def scan_local_file(file: Path) -> None:
    _run(file)


@app.command("scan-folder")
def scan_local_folder(folder: Path) -> None:
    _run(folder, True)


@app.command("scan-inventory")
def scan_inventory(inventory_file: Path) -> None:
    _run(inventory_file)


@app.command("jwt")
def jwt(input: Path) -> None:
    _run(input, input.is_dir(), "jwt")


@app.command("cookies")
def cookies(input: Path) -> None:
    _run(input, input.is_dir(), "cookies")


@app.command("headers")
def headers(input: Path) -> None:
    _run(input, input.is_dir(), "headers")


@app.command("cors")
def cors(input: Path) -> None:
    _run(input, input.is_dir(), "cors")


@app.command("cache")
def cache(input: Path) -> None:
    _run(input, input.is_dir(), "cache")


@app.command("report")
def report(input: Path, format: str = typer.Option("markdown", "--format")) -> None:
    try:
        inv = load_or_scan(input)
        typer.echo(
            render_markdown(inv)
            if format == "markdown"
            else render_json(inv)
            if format == "json"
            else (_ for _ in ()).throw(
                ValueError("Report format must be markdown or json")
            )
        )
    except (ValueError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc


@app.command("checklist")
def checklist(input: Path, format: str = typer.Option("markdown", "--format")) -> None:
    try:
        if format not in {"markdown", "json"}:
            raise ValueError("Checklist format must be markdown or json")
        typer.echo(render_checklist(load_or_scan(input), format))
    except (ValueError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
