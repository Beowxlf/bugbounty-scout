"""Synthetic demo project lifecycle commands."""

import json
import shutil
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Create and inspect a synthetic, local-only demo project.")
console = Console()

SAFETY = (
    "Authorized lab/demo use only. Synthetic local files only; no live requests, "
    "replay, fuzzing, payload generation, or real secrets."
)
REQUIRED = (
    "inputs/fake.har",
    "inputs/fake_frontend.js",
    "inputs/fake_graphql.har",
    "inputs/fake_request.txt",
    "inputs/fake_response.txt",
    "outputs",
    "evidence",
    "reports",
    "README.md",
    "workflow.md",
    "scope.yml",
    "workflow.yml",
    ".bugbounty-scout-workflow",
)
WORKFLOW = f"""# Synthetic end-to-end workflow

> {SAFETY}

Run these commands from this demo directory. They read local files only:

```bash
bbs har report inputs/fake.har --format json
bbs endpoints from-har inputs/fake.har
bbs frontend scan-file inputs/fake_frontend.js
bbs auth-surface scan-har inputs/fake.har
bbs graphql scan-har inputs/fake_graphql.har
bbs paramforge scan-har inputs/fake.har
bbs authz init demo-authz
bbs evidence init "Demo finding"
bbs correlate scan outputs/
bbs correlate report correlation-project.yml --format markdown
```

The commands are instructions only and are not automatically executed.
"""


def _har(graphql: bool = False) -> dict:
    url = (
        "https://api.example.test/graphql"
        if graphql
        else "https://api.example.test/api/users/123?include=profile"
    )
    body = (
        '{"query":"query DemoUser($userId: ID!) { user(id: $userId) { id email } }",'
        '"variables":{"userId":"demo-user-123"}}'
        if graphql
        else '{"userId":"demo-user-123","displayName":"Synthetic User"}'
    )
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "BugBountyScout synthetic demo", "version": "1"},
            "entries": [
                {
                    "startedDateTime": "2026-01-01T00:00:00Z",
                    "time": 1,
                    "request": {
                        "method": "POST",
                        "url": url,
                        "httpVersion": "HTTP/1.1",
                        "headers": [
                            {"name": "Content-Type", "value": "application/json"}
                        ],
                        "queryString": [],
                        "cookies": [],
                        "headersSize": -1,
                        "bodySize": len(body),
                        "postData": {"mimeType": "application/json", "text": body},
                    },
                    "response": {
                        "status": 200,
                        "statusText": "OK",
                        "httpVersion": "HTTP/1.1",
                        "headers": [
                            {"name": "Content-Type", "value": "application/json"}
                        ],
                        "cookies": [],
                        "content": {
                            "size": 28,
                            "mimeType": "application/json",
                            "text": '{"status":"synthetic-demo"}',
                        },
                        "redirectURL": "",
                        "headersSize": -1,
                        "bodySize": 28,
                    },
                    "cache": {},
                    "timings": {"send": 0, "wait": 1, "receive": 0},
                }
            ],
        }
    }


@app.command("init")
def init_demo(demo_name: Path) -> None:
    """Create a deterministic synthetic demo project without running analyzers."""
    if demo_name.exists():
        console.print(f"[red]Error:[/red] Refusing to overwrite: {demo_name}")
        raise typer.Exit(2)
    try:
        for folder in ("inputs", "outputs", "evidence", "reports"):
            demo_name.joinpath(folder).mkdir(parents=True)
        demo_name.joinpath("inputs/fake.har").write_text(
            json.dumps(_har(), indent=2) + "\n", encoding="utf-8"
        )
        demo_name.joinpath("inputs/fake_graphql.har").write_text(
            json.dumps(_har(True), indent=2) + "\n", encoding="utf-8"
        )
        demo_name.joinpath("inputs/fake_frontend.js").write_text(
            'const api = "/api/users/123";\\nconst graphql = "/graphql";\\n',
            encoding="utf-8",
        )
        demo_name.joinpath("inputs/fake_request.txt").write_text(
            "GET /api/users/123 HTTP/1.1\nHost: api.example.test\n", encoding="utf-8"
        )
        demo_name.joinpath("inputs/fake_response.txt").write_text(
            'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"demo":true}\n',
            encoding="utf-8",
        )
        demo_name.joinpath("scope.yml").write_text(
            yaml.safe_dump(
                {
                    "program_name": "Synthetic Demo Program",
                    "platform": "local lab",
                    "in_scope": ["api.example.test"],
                    "out_of_scope": [],
                    "forbidden_tests": [
                        "live requests",
                        "request replay",
                        "fuzzing",
                        "exploit automation",
                    ],
                    "rate_limits": {},
                    "auth_notes": "Use synthetic demo artifacts only.",
                    "report_notes": "Review redaction before sharing.",
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        demo_name.joinpath("README.md").write_text(
            f"# BugBountyScout synthetic demo\n\n{SAFETY}\n\nSee `workflow.md`.\n",
            encoding="utf-8",
        )
        demo_name.joinpath("workflow.md").write_text(WORKFLOW, encoding="utf-8")
        from bugbounty_scout.models import WorkflowManifest
        from bugbounty_scout.modules.workflow import MARKER, save_manifest

        demo_name.joinpath(MARKER).write_text(
            "BugBountyScout Workflow Workspace v1\n", encoding="utf-8"
        )
        save_manifest(
            WorkflowManifest(
                id="workflow-synthetic-demo",
                project_name=demo_name.name,
                workspace_path=str(demo_name.resolve()),
            ),
            demo_name.resolve(),
        )
    except OSError as exc:
        console.print(f"[red]Error:[/red] Could not create demo: {exc}")
        raise typer.Exit(2) from exc
    console.print(f"[green]Created synthetic demo:[/green] {demo_name}")
    console.print(SAFETY)


@app.command("status")
def status_demo(demo_folder: Path) -> None:
    """Show whether required synthetic demo files and directories exist."""
    if not demo_folder.is_dir():
        console.print(f"[red]Error:[/red] Demo folder does not exist: {demo_folder}")
        raise typer.Exit(2)
    table = Table(title=f"Demo status: {demo_folder}")
    table.add_column("Path")
    table.add_column("Status")
    complete = True
    for relative in REQUIRED:
        exists = demo_folder.joinpath(relative).exists()
        complete &= exists
        table.add_row(relative, "present" if exists else "missing")
    console.print(table)
    console.print(SAFETY)
    if not complete:
        raise typer.Exit(1)


@app.command("clean")
def clean_demo(
    demo_folder: Path,
) -> None:
    """Remove a generated demo after verifying its safety marker."""
    marker = demo_folder / "workflow.md"
    if not demo_folder.is_dir() or not marker.is_file():
        console.print("[red]Error:[/red] Not a recognized demo folder.")
        raise typer.Exit(2)
    if "Synthetic end-to-end workflow" not in marker.read_text(encoding="utf-8"):
        console.print("[red]Error:[/red] Demo safety marker is missing.")
        raise typer.Exit(2)
    shutil.rmtree(demo_folder)
    console.print(f"[green]Removed demo:[/green] {demo_folder}")
