"""Local environment readiness checks."""

import importlib
import json
import os
import sys
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.table import Table

from bugbounty_scout import __version__
from bugbounty_scout.redaction import redact_text

console = Console()


def collect_checks() -> dict[str, object]:
    """Collect deterministic, network-free environment checks."""
    cwd = Path.cwd()
    runtime = {}
    for name in ("typer", "pydantic", "yaml", "rich"):
        try:
            importlib.import_module(name)
            runtime[name] = True
        except ImportError:
            runtime[name] = False
    dev = {}
    for name in ("pytest", "ruff"):
        try:
            importlib.import_module(name)
            dev[name] = True
        except ImportError:
            dev[name] = False
    redacted = redact_text("Authorization: Bearer synthetic-demo-token")
    parsing_ok = (
        json.loads('{"safe": true}')["safe"] and yaml.safe_load("safe: true")["safe"]
    )
    argv0 = Path(sys.argv[0]).name
    module_invocation = argv0 in {"python", "python3", "cli.py", "__main__.py"}
    pythonpath = os.environ.get("PYTHONPATH", "")
    fallback = "src" in pythonpath.split(os.pathsep) or any(
        Path(item).name == "src" for item in sys.path if item
    )
    return {
        "python_version": sys.version.split()[0],
        "bugbounty_scout_version": __version__,
        "runtime_imports": runtime,
        "dev_imports": dev,
        "cwd": str(cwd),
        "paths": {
            "fixtures": (cwd / "fixtures").is_dir(),
            "fixtures/endpoints": (cwd / "fixtures/endpoints").is_dir(),
            "rules": (cwd / "rules").is_dir(),
            "docs": (cwd / "docs").is_dir(),
        },
        "console_script": argv0 == "bbs",
        "pythonpath_fallback": fallback or module_invocation,
        "redaction_sanity": "synthetic-demo-token" not in redacted,
        "json_yaml_sanity": bool(parsing_ok),
        "network_requests": False,
    }


def _status(value: object) -> str:
    if isinstance(value, bool):
        return "PASS" if value else "NOT FOUND"
    return str(value)


def doctor(
    format: str = typer.Option(
        "table", "--format", help="Output format: table or json."
    ),
) -> None:
    """Check local installation readiness without making network requests."""
    checks = collect_checks()
    value = format.lower()
    if value == "json":
        typer.echo(json.dumps(checks, indent=2))
        return
    if value != "table":
        raise typer.BadParameter("must be 'table' or 'json'")
    table = Table(title="BugBountyScout doctor (local checks only)")
    table.add_column("Check")
    table.add_column("Result")
    table.add_row("Python version", str(checks["python_version"]))
    table.add_row("BugBountyScout version", str(checks["bugbounty_scout_version"]))
    for name, ok in checks["runtime_imports"].items():
        table.add_row(f"Runtime import: {name}", _status(ok))
    for name, ok in checks["dev_imports"].items():
        table.add_row(f"Optional dev import: {name}", _status(ok))
    table.add_row("Current working directory", str(checks["cwd"]))
    for name, ok in checks["paths"].items():
        table.add_row(f"Path: {name}", _status(ok))
    table.add_row("Running as installed `bbs`", _status(checks["console_script"]))
    table.add_row("PYTHONPATH/module fallback", _status(checks["pythonpath_fallback"]))
    table.add_row("Redaction sanity", _status(checks["redaction_sanity"]))
    table.add_row("JSON/YAML parsing", _status(checks["json_yaml_sanity"]))
    console.print(table)
    console.print(
        "No network requests were made. Missing optional development tools do not "
        "prevent normal runtime use."
    )
