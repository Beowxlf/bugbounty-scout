"""Local-only workflow orchestration for existing passive modules."""

import hashlib
import json
import shutil
import time
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import yaml

from bugbounty_scout.config import load_data
from bugbounty_scout.har import analyze_har
from bugbounty_scout.har import render_json as har_json
from bugbounty_scout.har import render_markdown as har_markdown
from bugbounty_scout.models import (
    Reportability,
    WorkflowInput,
    WorkflowInputType,
    WorkflowManifest,
    WorkflowOutput,
    WorkflowOutputType,
    WorkflowStep,
    WorkflowStepStatus,
    WorkflowSummary,
)
from bugbounty_scout.modules import (
    auth_surface,
    correlator,
    endpoints,
    frontend,
    graphql_mapper,
    paramforge,
)
from bugbounty_scout.modules.frontend_reporting import render_json as frontend_json
from bugbounty_scout.modules.frontend_reporting import (
    render_markdown as frontend_markdown,
)
from bugbounty_scout.modules.passive_api import (
    render_inventory_json,
    render_inventory_markdown,
)

MARKER = ".bugbounty-scout-workflow"
INPUT_FOLDERS = (
    "har",
    "frontend",
    "graphql",
    "requests",
    "responses",
    "inventories",
    "evidence",
    "authz",
    "other",
)
OUTPUT_FOLDERS = (
    "har",
    "endpoints",
    "frontend",
    "auth_surface",
    "graphql",
    "paramforge/wordlists",
    "authz",
    "evidence",
    "correlate",
)
PIPELINE = (
    ("har", "HAR Analyzer", "har-analyzer"),
    ("endpoints", "Endpoint Mapper", "endpoint-mapper"),
    ("frontend", "Frontend Exposure Analyzer", "frontend-exposure-analyzer"),
    ("auth_surface", "Auth Surface Analyzer", "auth-surface-analyzer"),
    ("graphql", "GraphQL Risk Mapper", "graphql-risk-mapper"),
    ("paramforge", "ParamForge", "paramforge"),
    ("correlate", "Project Correlator", "project-correlator"),
    ("summary", "Summary/report generation", "workflow-orchestrator"),
)


def _now() -> datetime:
    return datetime.now(UTC)


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _id(prefix: str, value: str) -> str:
    return f"{prefix}-{hashlib.sha256(value.encode()).hexdigest()[:12]}"


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        content + ("" if content.endswith("\n") else "\n"), encoding="utf-8"
    )
    return path


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def workspace_readme(name: str) -> str:
    return f"""# {name} BugBountyScout workflow

This is a local-only, passive/manual-first workbench.

1. Put local files in the appropriate `inputs/` folders.
2. Do not store real secrets unless you understand the local storage risk.
3. Generated reports redact sensitive values by default.
4. No live requests are made, and captured requests are never replayed.

```bash
bbs workflow detect {name}
bbs workflow run {name}
bbs workflow status {name}
bbs workflow report {name} --format markdown
```

Only use these artifacts for authorized bug bounty, owned-asset, or lab work.
"""


def initialize_workspace(root: Path) -> WorkflowManifest:
    root = root.resolve()
    if root.exists():
        raise FileExistsError(f"Refusing to overwrite existing path: {root}")
    for folder in INPUT_FOLDERS:
        (root / "inputs" / folder).mkdir(parents=True, exist_ok=True)
    for folder in OUTPUT_FOLDERS:
        (root / "outputs" / folder).mkdir(parents=True, exist_ok=True)
    for folder in ("reports", "logs", "evidence"):
        (root / folder).mkdir(parents=True, exist_ok=True)
    (root / MARKER).write_text(
        "BugBountyScout Workflow Workspace v1\n", encoding="utf-8"
    )
    (root / "README.md").write_text(workspace_readme(root.name), encoding="utf-8")
    (root / "scope.yml").write_text(
        yaml.safe_dump(
            {
                "program_name": root.name,
                "platform": "",
                "in_scope": [],
                "out_of_scope": [],
                "forbidden_tests": ["live requests", "request replay", "fuzzing"],
                "rate_limits": {},
                "auth_notes": "",
                "report_notes": "Review redaction before sharing reports.",
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    manifest = WorkflowManifest(
        id=f"workflow-{uuid4().hex[:12]}",
        project_name=root.name,
        workspace_path=str(root),
    )
    save_manifest(manifest, root)
    return manifest


def is_workspace(root: Path) -> bool:
    return (root / MARKER).is_file() and (root / "workflow.yml").is_file()


def load_manifest(root: Path) -> WorkflowManifest:
    path = root / "workflow.yml"
    if not path.is_file():
        raise ValueError(f"Workflow manifest not found: {path}")
    return WorkflowManifest.model_validate(load_data(path))


def save_manifest(manifest: WorkflowManifest, root: Path) -> Path:
    manifest.updated_at = _now()
    path = root / "workflow.yml"
    path.write_text(
        yaml.safe_dump(manifest.model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )
    return path


def _structured_type(path: Path) -> WorkflowInputType | None:
    if path.suffix.lower() not in {".json", ".yml", ".yaml"}:
        return None
    try:
        data = load_data(path)
    except ValueError:
        return None
    keys = set(data)
    if "endpoints" in keys and {"source_files", "project_name"} & keys:
        return WorkflowInputType.ENDPOINT_INVENTORY
    if {"secrets", "source_maps", "storage_references"} & keys:
        return WorkflowInputType.FRONTEND_INVENTORY
    if {"jwt_observations", "cookie_observations", "cors_observations"} & keys:
        return WorkflowInputType.AUTH_SURFACE_INVENTORY
    if {"operations", "schema_artifacts", "review_leads"} & keys:
        return WorkflowInputType.GRAPHQL_INVENTORY
    if "terms" in keys and "categories" in keys:
        return WorkflowInputType.PARAMFORGE_INVENTORY
    if {"actors", "objects", "expected_access"} <= keys:
        return WorkflowInputType.AUTHZ_MATRIX
    if "evidence_items" in keys:
        return WorkflowInputType.EVIDENCE_WORKSPACE
    if {"artifacts", "assets", "triage_leads"} <= keys:
        return WorkflowInputType.CORRELATION_PROJECT
    return None


def classify(path: Path) -> tuple[WorkflowInputType, list[str], list[str]]:
    suffix = path.suffix.lower()
    structured = _structured_type(path)
    if structured:
        mapping = {
            WorkflowInputType.ENDPOINT_INVENTORY: [
                "Project Correlator",
                "ParamForge",
                "Authz import",
            ],
            WorkflowInputType.FRONTEND_INVENTORY: ["Project Correlator", "ParamForge"],
            WorkflowInputType.AUTH_SURFACE_INVENTORY: ["Project Correlator"],
            WorkflowInputType.GRAPHQL_INVENTORY: ["Project Correlator"],
            WorkflowInputType.PARAMFORGE_INVENTORY: ["Project Correlator"],
            WorkflowInputType.AUTHZ_MATRIX: ["Project Correlator"],
            WorkflowInputType.EVIDENCE_WORKSPACE: [
                "Project Correlator",
                "Report Quality Gate",
            ],
            WorkflowInputType.CORRELATION_PROJECT: ["Project Correlator"],
        }
        return structured, mapping[structured], []
    if suffix == ".har":
        modules = [
            "HAR Analyzer",
            "Endpoint Mapper",
            "Auth Surface Analyzer",
            "ParamForge",
        ]
        try:
            if "graphql" in path.read_text(encoding="utf-8", errors="ignore").lower():
                modules.append("GraphQL Risk Mapper")
        except OSError:
            pass
        return WorkflowInputType.HAR, modules, []
    if suffix in {".js", ".mjs", ".cjs"}:
        modules = ["Frontend Exposure Analyzer", "Endpoint Mapper", "ParamForge"]
        text = path.read_text(encoding="utf-8", errors="ignore").lower()
        if "graphql" in text or "query " in text or "mutation " in text:
            modules.append("GraphQL Risk Mapper")
        return WorkflowInputType.JAVASCRIPT, modules, []
    if suffix in {".html", ".htm"}:
        return (
            WorkflowInputType.HTML,
            ["Frontend Exposure Analyzer", "Endpoint Mapper", "ParamForge"],
            [],
        )
    if suffix in {".graphql", ".gql"}:
        return WorkflowInputType.GRAPHQL, ["GraphQL Risk Mapper", "ParamForge"], []
    if suffix == ".map":
        return (
            WorkflowInputType.SOURCE_MAP,
            ["Frontend Exposure Analyzer", "ParamForge"],
            [],
        )
    if suffix in {".txt", ".http"}:
        text = path.read_text(encoding="utf-8", errors="ignore").lstrip()
        if text.startswith("HTTP/"):
            return (
                WorkflowInputType.RAW_RESPONSE,
                ["Auth Surface Analyzer", "Evidence Locker"],
                [],
            )
        if any(
            text.startswith(f"{method} ")
            for method in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD")
        ):
            return (
                WorkflowInputType.RAW_REQUEST,
                ["Auth Surface Analyzer", "Evidence Locker"],
                [],
            )
        return WorkflowInputType.TEXT, ["ParamForge"], []
    if suffix == ".json":
        return WorkflowInputType.JSON, ["ParamForge"], ["Unrecognized JSON structure"]
    if suffix in {".yml", ".yaml"}:
        return WorkflowInputType.YAML, ["ParamForge"], ["Unrecognized YAML structure"]
    return WorkflowInputType.UNKNOWN, [], ["No supported local parser identified"]


def detect(root_or_inputs: Path) -> tuple[WorkflowManifest, Path]:
    root_or_inputs = root_or_inputs.resolve()
    if is_workspace(root_or_inputs):
        root, input_dir = root_or_inputs, root_or_inputs / "inputs"
        manifest = load_manifest(root)
    elif root_or_inputs.name == "inputs" and is_workspace(root_or_inputs.parent):
        root, input_dir = root_or_inputs.parent, root_or_inputs
        manifest = load_manifest(root)
    else:
        root, input_dir = root_or_inputs, root_or_inputs
        manifest_path = root / "workflow.yml"
        manifest = (
            load_manifest(root)
            if manifest_path.is_file()
            else WorkflowManifest(
                id=f"workflow-{uuid4().hex[:12]}",
                project_name=root.name,
                workspace_path=str(root),
                input_dir=".",
            )
        )
    if not input_dir.is_dir():
        raise ValueError(f"Input folder does not exist: {input_dir}")
    found = []
    for path in sorted(p for p in input_dir.rglob("*") if p.is_file()):
        if path.name in {"workflow.yml", MARKER}:
            continue
        input_type, modules, notes = classify(path)
        found.append(
            WorkflowInput(
                id=_id("input", _relative(path, root)),
                path=_relative(path, root),
                input_type=input_type,
                size_bytes=path.stat().st_size,
                sha256=_hash(path),
                detected_modules=modules,
                notes=notes,
            )
        )
    manifest.inputs = found
    manifest.summary.total_inputs = len(found)
    save_manifest(manifest, root)
    return manifest, root


def _record_output(
    manifest: WorkflowManifest,
    root: Path,
    path: Path,
    output_type: WorkflowOutputType,
    step: WorkflowStep,
) -> None:
    relative = _relative(path, root)
    step.output_paths.append(relative)
    manifest.outputs.append(
        WorkflowOutput(
            id=_id("output", relative),
            path=relative,
            output_type=output_type,
            source_step_id=step.id,
            source_module=step.module,
            sha256=_hash(path),
            size_bytes=path.stat().st_size,
        )
    )


def _inputs(
    manifest: WorkflowManifest, *types: WorkflowInputType
) -> list[WorkflowInput]:
    return [item for item in manifest.inputs if item.input_type in types]


def _run_step(manifest: WorkflowManifest, root: Path, step: WorkflowStep) -> None:
    step.started_at = _now()
    step.status = WorkflowStepStatus.RUNNING
    started = time.monotonic()
    try:
        if step.id == "har":
            items = _inputs(manifest, WorkflowInputType.HAR)
            if not items:
                raise LookupError("No HAR inputs were detected.")
            analyses = [analyze_har(root / item.path) for item in items]
            primary = analyses[0]
            paths = [
                _write(root / "outputs/har/har-summary.json", har_json(primary)),
                _write(root / "outputs/har/har-report.md", har_markdown(primary)),
            ]
            for path, kind in zip(
                paths,
                (WorkflowOutputType.HAR_REPORT, WorkflowOutputType.MARKDOWN_REPORT),
                strict=True,
            ):
                _record_output(manifest, root, path, kind, step)
            if len(analyses) > 1:
                step.warning_messages.append(
                    "Deterministic summary uses the first HAR; all HARs are consumed by later folder-based modules."
                )
        elif step.id == "endpoints":
            candidates = _inputs(
                manifest,
                WorkflowInputType.HAR,
                WorkflowInputType.JAVASCRIPT,
                WorkflowInputType.HTML,
            )
            if not candidates:
                raise LookupError("No HAR, JavaScript, or HTML inputs were detected.")
            inventory = endpoints.inventory_from_folder(root / manifest.input_dir)
            paths = [
                _write(
                    root / "outputs/endpoints/endpoint-inventory.json",
                    render_inventory_json(inventory),
                ),
                _write(
                    root / "outputs/endpoints/endpoint-report.md",
                    render_inventory_markdown(inventory),
                ),
            ]
            for path, kind in zip(
                paths,
                (
                    WorkflowOutputType.ENDPOINT_INVENTORY,
                    WorkflowOutputType.MARKDOWN_REPORT,
                ),
                strict=True,
            ):
                _record_output(manifest, root, path, kind, step)
        elif step.id == "frontend":
            candidates = _inputs(
                manifest,
                WorkflowInputType.JAVASCRIPT,
                WorkflowInputType.HTML,
                WorkflowInputType.SOURCE_MAP,
            )
            if not candidates:
                raise LookupError("No frontend or source-map inputs were detected.")
            inventory = frontend.scan_folder(root / manifest.input_dir)
            paths = [
                _write(
                    root / "outputs/frontend/frontend-inventory.json",
                    frontend_json(inventory),
                ),
                _write(
                    root / "outputs/frontend/frontend-report.md",
                    frontend_markdown(inventory),
                ),
            ]
            for path, kind in zip(
                paths,
                (
                    WorkflowOutputType.FRONTEND_INVENTORY,
                    WorkflowOutputType.MARKDOWN_REPORT,
                ),
                strict=True,
            ):
                _record_output(manifest, root, path, kind, step)
        elif step.id == "auth_surface":
            candidates = _inputs(
                manifest,
                WorkflowInputType.HAR,
                WorkflowInputType.RAW_REQUEST,
                WorkflowInputType.RAW_RESPONSE,
            )
            if not candidates:
                raise LookupError("No HAR or raw HTTP inputs were detected.")
            inventory = auth_surface.scan_folder(root / manifest.input_dir)
            paths = [
                _write(
                    root / "outputs/auth_surface/auth-surface-inventory.json",
                    auth_surface.render_json(inventory),
                ),
                _write(
                    root / "outputs/auth_surface/auth-surface-report.md",
                    auth_surface.render_markdown(inventory),
                ),
            ]
            for path, kind in zip(
                paths,
                (
                    WorkflowOutputType.AUTH_SURFACE_INVENTORY,
                    WorkflowOutputType.MARKDOWN_REPORT,
                ),
                strict=True,
            ):
                _record_output(manifest, root, path, kind, step)
        elif step.id == "graphql":
            candidates = _inputs(manifest, WorkflowInputType.GRAPHQL)
            candidates += [
                item
                for item in _inputs(
                    manifest, WorkflowInputType.HAR, WorkflowInputType.JAVASCRIPT
                )
                if "GraphQL Risk Mapper" in item.detected_modules
            ]
            if not candidates:
                raise LookupError("No GraphQL-bearing local inputs were detected.")
            inventory = graphql_mapper.scan_folder(root / manifest.input_dir)
            paths = [
                _write(
                    root / "outputs/graphql/graphql-inventory.json",
                    graphql_mapper.render_json(inventory),
                ),
                _write(
                    root / "outputs/graphql/graphql-report.md",
                    graphql_mapper.render_markdown(inventory),
                ),
            ]
            for path, kind in zip(
                paths,
                (
                    WorkflowOutputType.GRAPHQL_INVENTORY,
                    WorkflowOutputType.MARKDOWN_REPORT,
                ),
                strict=True,
            ):
                _record_output(manifest, root, path, kind, step)
        elif step.id == "paramforge":
            candidates = [
                item
                for item in manifest.inputs
                if "ParamForge" in item.detected_modules
            ]
            if not candidates:
                raise LookupError(
                    "No ParamForge-compatible local inputs were detected."
                )
            inventory = paramforge.scan_folder(root / manifest.input_dir)
            inventory_path = _write(
                root / "outputs/paramforge/paramforge-inventory.json",
                paramforge.render_json(inventory),
            )
            _record_output(
                manifest,
                root,
                inventory_path,
                WorkflowOutputType.PARAMFORGE_INVENTORY,
                step,
            )
            for path in paramforge.export_all(
                inventory, root / "outputs/paramforge/wordlists"
            ):
                _record_output(manifest, root, path, WorkflowOutputType.CHECKLIST, step)
        elif step.id == "correlate":
            artifacts = [
                item
                for item in manifest.outputs
                if item.output_type
                not in {
                    WorkflowOutputType.MARKDOWN_REPORT,
                    WorkflowOutputType.CHECKLIST,
                }
            ]
            existing = _inputs(
                manifest,
                WorkflowInputType.AUTHZ_MATRIX,
                WorkflowInputType.EVIDENCE_WORKSPACE,
            )
            if not artifacts and not existing:
                raise LookupError(
                    "No module inventories, authz matrix, or evidence workspace are available."
                )
            project_path = correlator.scan(
                root, root / "outputs/correlate/correlation-project.yml"
            )
            project = correlator.load_project(project_path)
            report_path = _write(
                root / "outputs/correlate/correlation-report.md",
                correlator.render_markdown(project),
            )
            leads_path = _write(
                root / "outputs/correlate/triage-leads.json",
                correlator.render_leads(project, "json"),
            )
            checklist_path = _write(
                root / "outputs/correlate/manual-checklist.md",
                correlator.render_checklist(project, "markdown"),
            )
            for path, kind in (
                (project_path, WorkflowOutputType.CORRELATION_PROJECT),
                (report_path, WorkflowOutputType.CORRELATION_REPORT),
                (leads_path, WorkflowOutputType.TRIAGE_LEADS),
                (checklist_path, WorkflowOutputType.CHECKLIST),
            ):
                _record_output(manifest, root, path, kind, step)
            manifest.correlation_project = _relative(project_path, root)
        elif step.id == "summary":
            update_summary(manifest, root)
            md = _write(
                root / "reports/project-summary.md",
                render_summary(manifest, "markdown"),
            )
            js = _write(
                root / "reports/project-summary.json", render_summary(manifest, "json")
            )
            _record_output(manifest, root, md, WorkflowOutputType.MARKDOWN_REPORT, step)
            _record_output(manifest, root, js, WorkflowOutputType.JSON_REPORT, step)
        step.status = WorkflowStepStatus.COMPLETED
    except LookupError as exc:
        step.status = WorkflowStepStatus.SKIPPED
        step.skipped_reason = str(exc)
    except Exception as exc:
        step.status = WorkflowStepStatus.FAILED
        step.error_message = f"{type(exc).__name__}: {exc}"
    finally:
        step.completed_at = _now()
        step.duration_seconds = round(time.monotonic() - started, 6)


def run(root: Path) -> WorkflowManifest:
    root = root.resolve()
    if not is_workspace(root):
        raise ValueError(f"Not a BugBountyScout workflow workspace: {root}")
    manifest, _ = detect(root)
    manifest.outputs = []
    manifest.steps = [
        WorkflowStep(
            id=key,
            name=name,
            module=module,
            input_ids=[item.id for item in manifest.inputs],
        )
        for key, name, module in PIPELINE
    ]
    for step in manifest.steps:
        _run_step(manifest, root, step)
        save_manifest(manifest, root)
    update_summary(manifest, root)
    save_manifest(manifest, root)
    return manifest


def update_summary(manifest: WorkflowManifest, root: Path) -> WorkflowSummary:
    leads = []
    if manifest.correlation_project and (root / manifest.correlation_project).is_file():
        with suppress(ValueError):
            leads = correlator.load_project(
                root / manifest.correlation_project
            ).triage_leads
    high = [
        lead.model_dump(mode="json")
        for lead in leads
        if lead.priority.value in {"critical", "high"}
    ]
    ready = [
        lead.model_dump(mode="json")
        for lead in leads
        if lead.reportability == Reportability.REPORT_READY
    ]
    skipped = [
        step for step in manifest.steps if step.status == WorkflowStepStatus.SKIPPED
    ]
    failed = [
        step for step in manifest.steps if step.status == WorkflowStepStatus.FAILED
    ]
    warnings = [message for step in manifest.steps for message in step.warning_messages]
    warnings.extend(f"{step.name}: {step.error_message}" for step in failed)
    actions = [
        action for lead in leads[:5] for action in lead.manual_validation_steps[:2]
    ]
    if not actions:
        actions = [
            "Review the generated inventories and confirm scope before manual validation.",
            "Collect minimal redacted evidence for promising leads; do not replay requests automatically.",
        ]
    manifest.summary = WorkflowSummary(
        total_inputs=len(manifest.inputs),
        total_steps=len(manifest.steps),
        completed_steps=sum(
            step.status == WorkflowStepStatus.COMPLETED for step in manifest.steps
        ),
        skipped_steps=len(skipped),
        failed_steps=len(failed),
        total_outputs=len(manifest.outputs),
        high_priority_leads=high,
        report_ready_candidates=ready,
        needs_more_evidence_count=sum(
            lead.reportability == Reportability.NEEDS_MORE_EVIDENCE for lead in leads
        ),
        warnings=warnings,
        next_manual_actions=list(dict.fromkeys(actions))[:10],
    )
    return manifest.summary


def render_summary(manifest: WorkflowManifest, format: str = "markdown") -> str:
    if format == "json":
        return json.dumps(
            {
                "project_name": manifest.project_name,
                "workspace_path": manifest.workspace_path,
                "summary": manifest.summary.model_dump(mode="json"),
                "inputs": [item.model_dump(mode="json") for item in manifest.inputs],
                "steps": [item.model_dump(mode="json") for item in manifest.steps],
                "outputs": [item.model_dump(mode="json") for item in manifest.outputs],
                "redaction_notice": "Outputs are redacted by default; review before sharing.",
                "limitations": [
                    "Local passive analysis only",
                    "Findings and leads require manual validation",
                ],
            },
            indent=2,
        )
    completed = [
        step for step in manifest.steps if step.status == WorkflowStepStatus.COMPLETED
    ]
    skipped = [
        step for step in manifest.steps if step.status == WorkflowStepStatus.SKIPPED
    ]
    failed = [
        step for step in manifest.steps if step.status == WorkflowStepStatus.FAILED
    ]
    lines = [
        f"# Project summary: {manifest.project_name}",
        "",
        "> Authorized local-only passive analysis. No live requests or replay.",
        "",
        "## Summary",
        f"- Inputs: {manifest.summary.total_inputs}",
        f"- Completed steps: {len(completed)}",
        f"- Skipped steps: {len(skipped)}",
        f"- Failed steps: {len(failed)}",
        f"- Outputs: {manifest.summary.total_outputs}",
        f"- High-priority leads: {len(manifest.summary.high_priority_leads)}",
        f"- Report-ready candidates: {len(manifest.summary.report_ready_candidates)}",
        f"- Needs more evidence: {manifest.summary.needs_more_evidence_count}",
        "",
        "## Inputs",
        *[
            f"- `{item.path}` — {item.input_type.value} ({', '.join(item.detected_modules) or 'unclassified'})"
            for item in manifest.inputs
        ],
        "",
        "## Steps run",
        *[f"- {step.name}: {step.status.value}" for step in completed],
        "",
        "## Skipped steps",
        *([f"- {step.name}: {step.skipped_reason}" for step in skipped] or ["- None"]),
        "",
        "## Failed steps",
        *([f"- {step.name}: {step.error_message}" for step in failed] or ["- None"]),
        "",
        "## Outputs",
        *[f"- `{item.path}` ({item.output_type.value})" for item in manifest.outputs],
        "",
        "## Highest-priority correlator leads",
        *(
            [
                f"- {lead['title']} ({lead['priority']})"
                for lead in manifest.summary.high_priority_leads
            ]
            or ["- None identified"]
        ),
        "",
        "## Report-ready candidates",
        *(
            [f"- {lead['title']}" for lead in manifest.summary.report_ready_candidates]
            or ["- None identified"]
        ),
        "",
        "## Evidence gaps",
        f"- {manifest.summary.needs_more_evidence_count} lead(s) need more evidence.",
        "",
        "## Next manual actions",
        *[f"- {item}" for item in manifest.summary.next_manual_actions],
        "",
        "## Redaction notice",
        "Reports redact sensitive values by default. Review every artifact before sharing.",
        "",
        "## Limitations",
        "- Passive local-file analysis can produce false positives and incomplete context.",
        "- BugBountyScout does not validate findings, send requests, replay traffic, or exploit targets.",
    ]
    return "\n".join(lines) + "\n"


def render_report(manifest: WorkflowManifest, format: str = "markdown") -> str:
    if format == "json":
        return render_summary(manifest, "json")
    references = [
        item
        for item in manifest.outputs
        if item.output_type
        in {
            WorkflowOutputType.HAR_REPORT,
            WorkflowOutputType.ENDPOINT_INVENTORY,
            WorkflowOutputType.FRONTEND_INVENTORY,
            WorkflowOutputType.AUTH_SURFACE_INVENTORY,
            WorkflowOutputType.GRAPHQL_INVENTORY,
            WorkflowOutputType.PARAMFORGE_INVENTORY,
            WorkflowOutputType.CORRELATION_REPORT,
            WorkflowOutputType.TRIAGE_LEADS,
            WorkflowOutputType.CHECKLIST,
        }
    ]
    return (
        render_summary(manifest, "markdown")
        + "\n## Referenced module artifacts\n"
        + "".join(
            f"- `{item.path}` — {item.output_type.value}\n" for item in references
        )
    )


def clean(root: Path, outputs_only: bool = False) -> None:
    root = root.resolve()
    if not is_workspace(root):
        raise ValueError("Refusing to clean: workflow safety marker is missing.")
    if outputs_only:
        for name in ("outputs", "reports"):
            shutil.rmtree(root / name, ignore_errors=True)
        for folder in OUTPUT_FOLDERS:
            (root / "outputs" / folder).mkdir(parents=True, exist_ok=True)
        (root / "reports").mkdir(parents=True, exist_ok=True)
        manifest = load_manifest(root)
        manifest.outputs = []
        manifest.steps = []
        manifest.correlation_project = ""
        manifest.summary = WorkflowSummary(total_inputs=len(manifest.inputs))
        save_manifest(manifest, root)
        return
    shutil.rmtree(root)
