"""Passive HAR analysis CLI commands."""

import json
from collections.abc import Callable
from pathlib import Path

import typer
from pydantic import BaseModel
from rich.console import Console
from rich.table import Table

from bugbounty_scout.har import (
    analyze_cookies,
    analyze_har,
    analyze_headers,
    analyze_third_parties,
    detect_sensitive_material,
    extract_endpoints,
    parse_har,
    render_json,
    render_markdown,
)

app = typer.Typer(help="Analyze passive HAR captures locally and safely.")
console = Console()


def _run(function: Callable[[Path], object], har_file: Path) -> object:
    try:
        return function(har_file)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from None


def _json(value: object) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    elif isinstance(value, list):
        value = [
            item.model_dump(mode="json") if isinstance(item, BaseModel) else item
            for item in value
        ]
    return json.dumps(value, indent=2)


def _table(title: str, columns: list[str], rows: list[list[str]]) -> None:
    table = Table(title=title)
    for column in columns:
        table.add_column(column)
    for row in rows:
        table.add_row(*row)
    console.print(table)


@app.command("summary")
def summary(
    har_file: Path,
    json_output: bool = typer.Option(False, "--json", help="Print JSON output."),
) -> None:
    """Summarize HAR entries without making network requests."""
    result = _run(parse_har, har_file)
    if json_output:
        typer.echo(_json(result))
        return
    _table(
        f"HAR summary ({result.entry_count} entries)",
        ["Method", "URL", "Status", "MIME type"],
        [
            [entry.method, entry.url, str(entry.status), entry.mime_type]
            for entry in result.entries
        ],
    )


@app.command("endpoints")
def endpoints(
    har_file: Path,
    json_output: bool = typer.Option(False, "--json", help="Print JSON output."),
) -> None:
    """Extract and normalize captured endpoints."""
    result = _run(extract_endpoints, har_file)
    if json_output:
        typer.echo(_json(result))
        return
    _table(
        "HAR endpoints",
        ["Method", "Host", "Path", "Query names", "Status", "MIME", "Count"],
        [
            [
                item.method,
                item.host,
                item.path,
                ", ".join(item.query_parameters) or "—",
                ", ".join(map(str, item.status_codes)),
                ", ".join(item.mime_types),
                str(item.count),
            ]
            for item in result
        ],
    )


@app.command("secrets")
def secrets(
    har_file: Path,
    json_output: bool = typer.Option(False, "--json", help="Print JSON output."),
) -> None:
    """Locate sensitive material while redacting its value."""
    result = _run(detect_sensitive_material, har_file)
    if json_output:
        typer.echo(_json(result))
        return
    _table(
        "Sensitive material (values redacted)",
        ["Category", "Location", "Name", "Source URL", "Value"],
        [
            [
                item.category,
                item.location,
                item.name,
                item.source_url,
                item.redacted_value,
            ]
            for item in result
        ],
    )


@app.command("cookies")
def cookies(
    har_file: Path,
    json_output: bool = typer.Option(False, "--json", help="Print JSON output."),
) -> None:
    """Review captured cookies and response cookie attributes."""
    result = _run(analyze_cookies, har_file)
    if json_output:
        typer.echo(_json(result))
        return
    _table(
        "HAR cookie review",
        ["Name", "Type", "Source", "Secure", "HttpOnly", "SameSite", "Notes"],
        [
            [
                item.name,
                item.cookie_type,
                item.source,
                "yes" if item.secure else "no",
                "yes" if item.http_only else "no",
                item.same_site or "—",
                "; ".join(item.observations) or "—",
            ]
            for item in result
        ],
    )


@app.command("headers")
def headers(
    har_file: Path,
    json_output: bool = typer.Option(False, "--json", help="Print JSON output."),
) -> None:
    """Review security-relevant response headers conservatively."""
    result = _run(analyze_headers, har_file)
    if json_output:
        typer.echo(_json(result))
        return
    _table(
        "HAR header review",
        ["Header", "Classification", "Value", "Observation"],
        [
            [item.header, item.classification, item.value, item.observation]
            for item in result
        ],
    )


@app.command("third-parties")
def third_parties(
    har_file: Path,
    json_output: bool = typer.Option(False, "--json", help="Print JSON output."),
) -> None:
    """Map captured third-party hosts and sensitive-data categories."""
    result = _run(analyze_third_parties, har_file)
    if json_output:
        typer.echo(_json(result))
        return
    _table(
        "HAR third-party leakage map",
        ["Host", "Requests", "Methods", "Sensitive categories", "Source URLs"],
        [
            [
                item.host,
                str(item.request_count),
                ", ".join(item.methods),
                ", ".join(item.sensitive_categories) or "none observed",
                ", ".join(item.source_urls),
            ]
            for item in result
        ],
    )


@app.command("report")
def report(
    har_file: Path,
    format: str = typer.Option("markdown", "--format", case_sensitive=False),
    output: Path | None = typer.Option(None, "--output", "-o"),
) -> None:
    """Generate a redacted Markdown or JSON HAR analysis report."""
    if format not in {"markdown", "json"}:
        console.print("[red]Error:[/red] --format must be 'markdown' or 'json'")
        raise typer.Exit(2)
    result = _run(analyze_har, har_file)
    content = render_markdown(result) if format == "markdown" else render_json(result)
    if output:
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                content + ("" if content.endswith("\n") else "\n"), encoding="utf-8"
            )
        except OSError as exc:
            console.print(f"[red]Error:[/red] Could not write report: {exc}")
            raise typer.Exit(2) from None
        console.print(f"[green]Wrote HAR report:[/green] {output}")
    else:
        typer.echo(content)
