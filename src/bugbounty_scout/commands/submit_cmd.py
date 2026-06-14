"""ReportForge local submission-draft and package commands."""

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from bugbounty_scout.models import PlatformProfile
from bugbounty_scout.modules import reportforge
from bugbounty_scout.modules.submission_packager import build_package

app = typer.Typer(
    help="Create redacted local report drafts and packages for manual submission."
)
console = Console()


def _fail(exc: Exception) -> None:
    console.print(f"[red]Error:[/red] {exc}")
    raise typer.Exit(2) from exc


def _write(draft, output: Path | None = None) -> Path:
    output = output or Path(f"{reportforge.slugify(draft.title)}-submission.yml")
    reportforge.save_draft(draft, output)
    typer.echo(str(output))
    return output


@app.command("from-evidence")
def from_evidence(evidence_workspace: Path, output: Path | None = None) -> None:
    try:
        _write(reportforge.from_evidence(evidence_workspace), output)
    except (ValueError, OSError) as exc:
        _fail(exc)


@app.command("from-lead")
def from_lead(
    correlation_project: Path,
    lead_id: str = typer.Option(..., "--lead-id"),
    output: Path | None = None,
) -> None:
    try:
        _write(reportforge.from_lead(correlation_project, lead_id), output)
    except (ValueError, OSError) as exc:
        _fail(exc)


@app.command("from-workflow")
def from_workflow(workflow_workspace: Path, output_dir: Path = Path(".")) -> None:
    try:
        drafts = reportforge.from_workflow(workflow_workspace)
        if not drafts:
            raise ValueError(
                "Workflow contains no evidence workspaces or correlator leads."
            )
        for draft in drafts:
            _write(
                draft,
                output_dir / f"{reportforge.slugify(draft.title)}-submission.yml",
            )
    except (ValueError, OSError) as exc:
        _fail(exc)


@app.command("from-finding")
def from_finding(finding_file: Path, output: Path | None = None) -> None:
    try:
        _write(reportforge.from_finding(finding_file), output)
    except (ValueError, OSError) as exc:
        _fail(exc)


@app.command("lint")
def lint(draft_or_package: Path) -> None:
    try:
        draft = reportforge.load_draft(draft_or_package)
        blocking, warnings = reportforge.lint_draft(draft)
        typer.echo(json.dumps({"blocking": blocking, "warnings": warnings}, indent=2))
        if blocking:
            raise typer.Exit(1)
    except typer.Exit:
        raise
    except (ValueError, OSError) as exc:
        _fail(exc)


@app.command("checklist")
def checklist(
    draft_or_package: Path,
    format: str = typer.Option("markdown", "--format"),
) -> None:
    try:
        if format not in {"markdown", "json"}:
            raise ValueError("Checklist format must be markdown or json.")
        typer.echo(
            reportforge.render_checklist(
                reportforge.load_draft(draft_or_package), format
            )
        )
    except (ValueError, OSError) as exc:
        _fail(exc)


@app.command("preview")
def preview(draft_or_package: Path) -> None:
    try:
        draft = reportforge.load_draft(draft_or_package)
        blocking, warnings = reportforge.lint_draft(draft)
        console.print(f"[bold]{draft.title}[/bold]")
        console.print(f"Platform profile: {draft.platform_profile.value}")
        console.print(f"Severity: {draft.severity_estimate.value}")
        console.print(f"Affected assets: {', '.join(draft.affected_assets) or 'none'}")
        console.print(f"Status: {draft.status.value}")
        console.print(f"Blocking issues: {len(blocking)}")
        console.print(f"Warnings: {len(warnings)}")
        console.print(f"Attachments: {len(draft.attachments)}")
        for index, step in enumerate(draft.steps_to_reproduce[:3], 1):
            console.print(f"{index}. {step}")
    except (ValueError, OSError) as exc:
        _fail(exc)


@app.command("export")
def export(
    draft_or_package: Path,
    format: str = typer.Option("markdown", "--format"),
    output: Path | None = typer.Option(None, "--output", "-o"),
) -> None:
    try:
        draft = reportforge.load_draft(draft_or_package)
        if format == "markdown":
            content = reportforge.render_markdown(draft)
        elif format == "json":
            content = reportforge.render_json(draft)
        else:
            raise ValueError("Export format must be markdown or json.")
        if output:
            output.write_text(content, encoding="utf-8")
            typer.echo(str(output))
        else:
            typer.echo(content)
    except (ValueError, OSError) as exc:
        _fail(exc)


@app.command("attachments")
def attachments(draft_or_package: Path) -> None:
    try:
        draft = reportforge.load_draft(draft_or_package)
        table = Table(
            "Title", "Path", "Type", "SHA-256", "Bytes", "Redacted", "Include"
        )
        for item in draft.attachments:
            table.add_row(
                item.title,
                item.path,
                item.attachment_type.value,
                item.sha256,
                str(item.size_bytes),
                str(item.redacted),
                str(item.include_in_package),
            )
        console.print(table)
        typer.echo(
            json.dumps(
                [item.model_dump(mode="json") for item in draft.attachments], indent=2
            )
        )
    except (ValueError, OSError) as exc:
        _fail(exc)


@app.command("redact-check")
def redact_check(draft_or_package: Path) -> None:
    try:
        warnings = reportforge.redaction_findings(
            reportforge.load_draft(draft_or_package)
        )
        typer.echo(json.dumps({"redaction_warnings": warnings}, indent=2))
        if warnings:
            raise typer.Exit(1)
    except typer.Exit:
        raise
    except (ValueError, OSError) as exc:
        _fail(exc)


@app.command("package")
def package(
    draft_or_workspace: Path,
    platform: PlatformProfile = typer.Option(PlatformProfile.GENERIC, "--platform"),
    output: Path = typer.Option(Path("submission-package"), "--output", "-o"),
) -> None:
    try:
        draft = reportforge.load_draft(draft_or_workspace)
        package_model = build_package(draft, output, platform)
        typer.echo(json.dumps(package_model.model_dump(mode="json"), indent=2))
    except (ValueError, OSError) as exc:
        _fail(exc)
