"""Passive, local-only project artifact correlation and conservative triage."""

import json
from collections import defaultdict
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from bugbounty_scout.models import (
    ArtifactType,
    Confidence,
    CorrelatedAsset,
    LeadCategory,
    Priority,
    ProjectArtifact,
    ProjectCorrelationInventory,
    Reportability,
    RiskSignal,
    Severity,
    TriageLead,
)
from bugbounty_scout.modules.endpoints import normalize_path
from bugbounty_scout.redaction import redact_text

SUPPORTED = {".json", ".yml", ".yaml", ".md", ".markdown"}


def _id(prefix: str, *parts: object) -> str:
    return f"{prefix}-{sha256('|'.join(map(str, parts)).encode()).hexdigest()[:12]}"


def _load(path: Path) -> tuple[Any, str]:
    try:
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() in {".md", ".markdown"}:
            return {"markdown": text}, ""
        data = (
            json.loads(text) if path.suffix.lower() == ".json" else yaml.safe_load(text)
        )
        if not isinstance(data, dict):
            raise ValueError("top-level content must be an object")
        return data, ""
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
        return None, redact_text(str(exc))


def detect_artifact_type(path: Path, data: Any = None) -> ArtifactType:
    name = path.name.lower()
    keys = set(data) if isinstance(data, dict) else set()
    if path.suffix.lower() in {".md", ".markdown"}:
        return ArtifactType.MARKDOWN_REPORT
    checks = (
        ({"endpoints", "hosts"}, ArtifactType.ENDPOINT_INVENTORY),
        ({"operations", "schema_artifacts"}, ArtifactType.GRAPHQL_INVENTORY),
        (
            {"jwt_observations", "cookie_observations"},
            ArtifactType.AUTH_SURFACE_INVENTORY,
        ),
        ({"secrets", "source_maps"}, ArtifactType.FRONTEND_INVENTORY),
        ({"terms", "routes"}, ArtifactType.PARAMFORGE_INVENTORY),
        ({"actors", "objects", "expectations"}, ArtifactType.AUTHZ_MATRIX),
        ({"evidence_items", "reproduction_steps"}, ArtifactType.EVIDENCE_WORKSPACE),
    )
    for required, kind in checks:
        if required <= keys:
            return kind
    if {"title", "severity", "asset"} <= keys:
        return ArtifactType.FINDING
    if "har" in name or "har_findings" in keys or "sensitive_findings" in keys:
        return ArtifactType.HAR_REPORT
    if path.suffix.lower() == ".json":
        return ArtifactType.JSON_REPORT
    return ArtifactType.UNKNOWN


def artifact_from_path(
    path: Path, explicit: str | None = None
) -> tuple[ProjectArtifact, Any]:
    raw = path.read_bytes()
    data, error = _load(path)
    kind = ArtifactType(explicit) if explicit else detect_artifact_type(path, data)
    source = ""
    if isinstance(data, dict):
        source = str(data.get("source_module", ""))
    return (
        ProjectArtifact(
            id=_id("artifact", path.resolve(), sha256(raw).hexdigest()),
            artifact_type=kind,
            path=str(path),
            source_module=source or kind.value,
            sha256=sha256(raw).hexdigest(),
            parsed=not error,
            parse_error=error,
        ),
        data,
    )


def discover(folder: Path) -> list[Path]:
    if not folder.is_dir():
        raise ValueError(f"Folder does not exist: {folder}")
    return sorted(
        p for p in folder.rglob("*") if p.is_file() and p.suffix.lower() in SUPPORTED
    )


def _location(value: str, fallback_path: str = "") -> tuple[str, str]:
    parsed = urlsplit(value)
    return (parsed.hostname or "").lower(), parsed.path or fallback_path or value


def _asset_key(host: str, path: str, method: str) -> str:
    return f"{host}|{normalize_path(path or '/')}|{method.upper()}"


def _iter_items(data: dict[str, Any], names: tuple[str, ...]):
    for name in names:
        value = data.get(name, [])
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    yield name, item


def _severity(value: Any, default: str = "info") -> Severity:
    value = str(value or default).lower()
    return Severity(value) if value in Severity else Severity.INFO


def _confidence(value: Any) -> Confidence:
    value = str(value or "medium").lower()
    return Confidence(value) if value in Confidence else Confidence.MEDIUM


def _signal(
    artifact: ProjectArtifact,
    asset: CorrelatedAsset | None,
    kind: str,
    title: str,
    item: dict[str, Any],
    reason: str,
) -> RiskSignal:
    evidence = str(item.get("redacted_evidence") or item.get("evidence") or "")
    return RiskSignal(
        id=_id("signal", artifact.id, kind, item.get("id", title)),
        signal_type=kind,
        title=title,
        source_module=artifact.source_module,
        source_artifact_id=artifact.id,
        asset_id=asset.id if asset else "",
        severity=_severity(item.get("severity")),
        confidence=_confidence(item.get("confidence")),
        tags=sorted(set(item.get("risk_tags", []) or item.get("tags", []) or [kind])),
        evidence="",
        redacted_evidence=redact_text(evidence),
        reason=reason,
    )


def build(project: ProjectCorrelationInventory) -> ProjectCorrelationInventory:
    assets: dict[str, CorrelatedAsset] = {}
    signals: list[RiskSignal] = []
    evidence_ready: list[str] = []

    def asset_for(
        artifact: ProjectArtifact, item: dict[str, Any], *, gql: bool = False
    ):
        value = str(item.get("url") or item.get("asset") or item.get("path") or "")
        host, path = _location(value, str(item.get("path", "")))
        method = str(item.get("method", "UNKNOWN")).upper()
        if not path:
            return None
        key = _asset_key(host, path, method)
        result = assets.setdefault(
            key,
            CorrelatedAsset(
                id=_id("asset", key),
                asset_type="graphql_endpoint" if gql else "endpoint",
                host=host,
                path=path,
                method=method,
                normalized_path=normalize_path(path),
            ),
        )
        result.related_artifacts = sorted(set(result.related_artifacts + [artifact.id]))
        result.source_modules = sorted(
            set(result.source_modules + [artifact.source_module])
        )
        result.tags = sorted(
            set(result.tags + list(item.get("risk_tags", []) or item.get("tags", [])))
        )
        return result

    for artifact in project.artifacts:
        data, error = _load(Path(artifact.path))
        artifact.parsed, artifact.parse_error = not error, error
        if not isinstance(data, dict):
            continue
        kind = artifact.artifact_type
        if kind == ArtifactType.ENDPOINT_INVENTORY:
            for _, item in _iter_items(data, ("endpoints",)):
                asset = asset_for(artifact, item)
                if not asset:
                    continue
                asset.related_endpoints.append(str(item.get("id", "")))
                for tag in item.get("risk_tags", []):
                    if tag in {
                        "idor-candidate",
                        "state-changing",
                        "admin",
                        "billing",
                        "file-upload",
                        "file-download",
                        "export",
                        "invite",
                        "organization-management",
                        "permission-management",
                        "role-management",
                        "sensitive-data",
                    }:
                        signals.append(
                            _signal(
                                artifact,
                                asset,
                                tag,
                                f"Endpoint tagged {tag}",
                                item,
                                "Passive endpoint metadata indicates a manual-review lead.",
                            )
                        )
        elif kind == ArtifactType.FRONTEND_INVENTORY:
            for name, item in _iter_items(
                data,
                (
                    "secrets",
                    "source_maps",
                    "findings",
                    "storage_references",
                    "dom_review_leads",
                    "postmessage_leads",
                ),
            ):
                asset = asset_for(artifact, item)
                signal_type = str(item.get("type") or item.get("finding_type") or name)
                if asset:
                    asset.related_frontend_findings.append(str(item.get("id", "")))
                signals.append(
                    _signal(
                        artifact,
                        asset,
                        signal_type,
                        str(item.get("title") or f"Frontend {signal_type}"),
                        item,
                        "Local frontend analysis produced a review signal.",
                    )
                )
        elif kind == ArtifactType.AUTH_SURFACE_INVENTORY:
            names = (
                "jwt_observations",
                "cookie_observations",
                "security_header_observations",
                "cors_observations",
                "cache_observations",
                "auth_endpoints",
            )
            for name, item in _iter_items(data, names):
                asset = asset_for(artifact, item)
                tags = item.get("risk_tags", []) or [name.removesuffix("_observations")]
                for tag in tags:
                    if asset:
                        asset.related_auth_observations.append(str(item.get("id", "")))
                    signals.append(
                        _signal(
                            artifact,
                            asset,
                            str(tag),
                            str(item.get("title") or f"Auth surface: {tag}"),
                            item,
                            "Authentication, session, header, CORS, or cache metadata needs manual context review.",
                        )
                    )
        elif kind == ArtifactType.GRAPHQL_INVENTORY:
            endpoint_assets = {}
            for _, item in _iter_items(data, ("endpoints",)):
                asset = asset_for(artifact, item, gql=True)
                if asset:
                    endpoint_assets[str(item.get("id", ""))] = asset
            for _, item in _iter_items(data, ("operations", "review_leads")):
                asset = endpoint_assets.get(str(item.get("endpoint_id", "")))
                if asset:
                    asset.related_graphql_operations.append(str(item.get("id", "")))
                tags = item.get("risk_tags", []) or item.get("tags", [])
                for tag in tags or ["graphql-manual-review"]:
                    signals.append(
                        _signal(
                            artifact,
                            asset,
                            str(tag),
                            str(
                                item.get("title")
                                or item.get("name")
                                or f"GraphQL {tag}"
                            ),
                            item,
                            "GraphQL operation metadata indicates authorization or sensitive-field review.",
                        )
                    )
        elif kind == ArtifactType.AUTHZ_MATRIX:
            endpoints = {
                str(x.get("id")): x
                for x in data.get("endpoints", [])
                if isinstance(x, dict)
            }
            for item in data.get("findings", []) + data.get("observed_results", []):
                if not isinstance(item, dict):
                    continue
                ep = endpoints.get(str(item.get("endpoint_id")), {})
                merged = {**ep, **item}
                asset = asset_for(artifact, merged)
                observed = str(
                    item.get("observed") or item.get("observed_result") or ""
                )
                expected = str(
                    item.get("expected") or item.get("expected_result") or ""
                )
                mismatch = (
                    "deny" in expected.lower() and "allow" in observed.lower()
                ) or item.get("mismatch")
                tag = (
                    "authz-mismatch"
                    if mismatch
                    else str(item.get("type", "authz-review"))
                )
                if asset:
                    asset.related_authz_findings.append(str(item.get("id", "")))
                signals.append(
                    _signal(
                        artifact,
                        asset,
                        tag,
                        str(item.get("title") or "Authorization matrix observation"),
                        merged,
                        "Recorded expected and observed authorization behavior should be manually validated.",
                    )
                )
        elif kind == ArtifactType.EVIDENCE_WORKSPACE:
            asset = asset_for(
                artifact,
                {
                    "asset": (data.get("affected_assets") or [""])[0],
                    "method": data.get("method", "UNKNOWN"),
                },
            )
            ready = str(data.get("status", "")).lower() == "ready"
            complete = bool(
                data.get("impact")
                and data.get("evidence_items")
                and data.get("reproduction_steps")
                and data.get("severity_rationale")
            )
            tag = (
                "evidence-ready"
                if ready and complete and not data.get("quality_warnings")
                else "evidence-gap"
            )
            if asset:
                asset.related_evidence_workspaces.append(str(data.get("id", "")))
            signals.append(
                _signal(
                    artifact,
                    asset,
                    tag,
                    str(data.get("title", "Evidence workspace")),
                    data,
                    "Evidence workspace quality and completeness were assessed locally.",
                )
            )
            if tag == "evidence-ready":
                evidence_ready.append(str(data.get("id", "")))
        elif kind in {ArtifactType.HAR_REPORT, ArtifactType.FINDING}:
            items = (
                [data]
                if kind == ArtifactType.FINDING
                else [
                    x
                    for _, x in _iter_items(
                        data,
                        (
                            "findings",
                            "sensitive_findings",
                            "third_party_findings",
                            "header_findings",
                            "cookie_findings",
                            "cache_findings",
                        ),
                    )
                ]
            )
            for item in items:
                asset = asset_for(artifact, item)
                tag = str(item.get("type") or item.get("signal_type") or "har-review")
                signals.append(
                    _signal(
                        artifact,
                        asset,
                        tag,
                        str(item.get("title") or "HAR/finding review"),
                        item,
                        "Captured local evidence produced a passive review signal.",
                    )
                )

    grouped: dict[str, list[RiskSignal]] = defaultdict(list)
    for signal in signals:
        grouped[signal.asset_id].append(signal)
    leads = [
        _make_lead(asset, grouped[asset.id])
        for asset in assets.values()
        if grouped[asset.id]
    ]
    for asset in assets.values():
        asset.related_endpoints = sorted(set(filter(None, asset.related_endpoints)))
        asset.related_graphql_operations = sorted(
            set(filter(None, asset.related_graphql_operations))
        )
        asset.related_auth_observations = sorted(
            set(filter(None, asset.related_auth_observations))
        )
        asset.related_frontend_findings = sorted(
            set(filter(None, asset.related_frontend_findings))
        )
        asset.related_authz_findings = sorted(
            set(filter(None, asset.related_authz_findings))
        )
        asset.related_evidence_workspaces = sorted(
            set(filter(None, asset.related_evidence_workspaces))
        )
        asset.risk_score = score(grouped.get(asset.id, []))
    project.assets = sorted(assets.values(), key=lambda x: (-x.risk_score, x.id))
    project.signals = signals
    project.triage_leads = sorted(
        leads, key=lambda x: (-priority_score(x.priority), x.id)
    )
    project.source_files = [x.path for x in project.artifacts]
    project.summary = {
        "artifacts": len(project.artifacts),
        "assets": len(project.assets),
        "signals": len(signals),
        "triage_leads": len(leads),
        "report_ready": sum(
            x.reportability == Reportability.REPORT_READY for x in leads
        ),
        "evidence_workspaces_ready": len(evidence_ready),
    }
    return project


def score(signals: list[RiskSignal]) -> int:
    weights = {
        Severity.INFO: 2,
        Severity.LOW: 8,
        Severity.MEDIUM: 18,
        Severity.HIGH: 30,
        Severity.CRITICAL: 40,
    }
    total = max((weights[x.severity] for x in signals), default=0) + min(
        20, max(0, len(signals) - 1) * 5
    )
    tags = {tag for item in signals for tag in item.tags} | {
        x.signal_type for x in signals
    }
    total += 20 if "authz-mismatch" in tags else 0
    total += (
        10 if tags & {"state-changing", "sensitive-data", "sensitive-fields"} else 0
    )
    total += 12 if tags & {"cross-tenant", "cross-org"} else 0
    total += 12 if "evidence-ready" in tags else 0
    total -= 10 if "evidence-gap" in tags else 0
    return max(0, min(100, total))


def priority_for(value: int) -> Priority:
    if value >= 90:
        return Priority.CRITICAL
    if value >= 70:
        return Priority.HIGH
    if value >= 40:
        return Priority.MEDIUM
    if value >= 15:
        return Priority.LOW
    return Priority.INFORMATIONAL


def priority_score(value: Priority) -> int:
    return {
        Priority.CRITICAL: 5,
        Priority.HIGH: 4,
        Priority.MEDIUM: 3,
        Priority.LOW: 2,
        Priority.INFORMATIONAL: 1,
    }[value]


def _make_lead(asset: CorrelatedAsset, signals: list[RiskSignal]) -> TriageLead:
    tags = {tag for x in signals for tag in x.tags} | {x.signal_type for x in signals}
    value = score(signals)
    category = LeadCategory.NEEDS_MANUAL_REVIEW
    if "authz-mismatch" in tags and "idor-candidate" in tags:
        category = LeadCategory.IDOR_BOLA
    elif asset.asset_type == "graphql_endpoint" and tags & {
        "object-id-variable",
        "sensitive-fields",
        "state-changing",
    }:
        category = LeadCategory.GRAPHQL_AUTHORIZATION_REVIEW
    elif "source-map" in " ".join(tags):
        category = LeadCategory.SOURCE_MAP_REVIEW
    elif tags & {"cookie", "missing-httponly", "missing-secure"}:
        category = LeadCategory.SESSION_COOKIE_REVIEW
    elif "evidence-ready" in tags:
        category = LeadCategory.REPORT_READY_CANDIDATE
    noise = len(signals) == 1 and tags & {
        "missing-header",
        "public-identifier",
        "source-map-exposure",
    }
    ready = "evidence-ready" in tags
    reportability = (
        Reportability.REPORT_READY
        if ready
        else Reportability.LIKELY_NOISE
        if noise
        else Reportability.NEEDS_MORE_EVIDENCE
        if not any(x.redacted_evidence for x in signals)
        else Reportability.NEEDS_MANUAL_VALIDATION
    )
    if noise:
        category, value = LeadCategory.LIKELY_NOISE, min(value, 14)
    return TriageLead(
        id=_id("lead", asset.id, *sorted(x.id for x in signals)),
        title=f"Manual review: {asset.method} {asset.host}{asset.normalized_path}",
        category=category,
        affected_asset_id=asset.id,
        source_signals=[x.id for x in signals],
        priority=priority_for(value),
        confidence=Confidence.HIGH if len(signals) >= 3 else Confidence.MEDIUM,
        severity_estimate=max(
            (x.severity for x in signals), key=lambda x: list(Severity).index(x)
        ),
        reason=f"{len(signals)} passive signal(s) correlate to this asset; classification remains conservative until manual validation.",
        manual_validation_steps=[
            "Confirm the affected asset is in scope.",
            "Compare expected and observed behavior using an authorized manual workflow.",
            "Confirm impact without expanding access or collecting unnecessary data.",
        ],
        suggested_evidence_to_collect=[
            "Redacted request/response or local observation reference",
            "Expected versus actual behavior",
            "Impact statement and severity rationale",
        ],
        reportability=reportability,
        related_evidence=sorted(
            {
                x.source_artifact_id
                for x in signals
                if x.redacted_evidence or x.signal_type == "evidence-ready"
            }
        ),
    )


def save(project: ProjectCorrelationInventory, path: Path) -> Path:
    path.write_text(
        yaml.safe_dump(project.model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )
    return path


def load_project(path: Path) -> ProjectCorrelationInventory:
    data, error = _load(path)
    if error:
        raise ValueError(f"Invalid correlation project: {error}")
    return ProjectCorrelationInventory.model_validate(data)


def scan(folder: Path, output: Path | None = None) -> Path:
    artifacts = [artifact_from_path(path)[0] for path in discover(folder)]
    project = build(
        ProjectCorrelationInventory(project_name=folder.name, artifacts=artifacts)
    )
    return save(project, output or Path("correlation-project.yml"))


def render_json(project: ProjectCorrelationInventory) -> str:
    return json.dumps(project.model_dump(mode="json"), indent=2)


def checklist(project: ProjectCorrelationInventory) -> dict[str, list[str]]:
    return {
        "Highest-priority leads": [
            f"{x.priority.value}: {x.title}" for x in project.triage_leads[:10]
        ],
        "IDOR/BOLA validation": [
            x.title
            for x in project.triage_leads
            if x.category == LeadCategory.IDOR_BOLA
        ],
        "GraphQL authorization validation": [
            x.title for x in project.triage_leads if "graphql" in x.category.value
        ],
        "Frontend exposure validation": [
            x.title
            for x in project.triage_leads
            if x.category
            in {
                LeadCategory.SOURCE_MAP_REVIEW,
                LeadCategory.EXPOSED_SECRET_REVIEW,
                LeadCategory.FRONTEND_CONFIG_EXPOSURE,
            }
        ],
        "Auth/session validation": [
            x.title
            for x in project.triage_leads
            if x.category
            in {
                LeadCategory.JWT_REVIEW,
                LeadCategory.SESSION_COOKIE_REVIEW,
                LeadCategory.AUTH_FLOW_REVIEW,
            }
        ],
        "CORS/cache/header validation": [
            x.title
            for x in project.triage_leads
            if x.category in {LeadCategory.CORS_REVIEW, LeadCategory.CACHE_REVIEW}
        ],
        "Evidence needed before reporting": [
            x.title
            for x in project.triage_leads
            if x.reportability == Reportability.NEEDS_MORE_EVIDENCE
        ],
        "Likely noise to deprioritize": [
            x.title
            for x in project.triage_leads
            if x.reportability == Reportability.LIKELY_NOISE
        ],
        "Suggested next manual actions": [
            "Review only authorized assets.",
            "Collect minimal redacted evidence.",
            "Do not report weak signals without demonstrated security impact.",
        ],
    }


def render_checklist(
    project: ProjectCorrelationInventory, format: str = "markdown"
) -> str:
    data = checklist(project)
    if format == "json":
        return json.dumps(data, indent=2)
    return "\n\n".join(
        f"## {name}\n\n"
        + ("\n".join(f"- [ ] {redact_text(x)}" for x in items) or "- _None._")
        for name, items in data.items()
    )


def render_leads(project: ProjectCorrelationInventory, format: str = "markdown") -> str:
    if format == "json":
        return json.dumps(
            [x.model_dump(mode="json") for x in project.triage_leads], indent=2
        )
    chunks = ["# Project triage leads"]
    signals = {x.id: x for x in project.signals}
    for lead in project.triage_leads:
        chunks.append(
            f"## {redact_text(lead.title)}\n\n- **Category:** {lead.category.value}\n- **Priority:** {lead.priority.value}\n- **Reportability:** {lead.reportability.value}\n- **Reason:** {redact_text(lead.reason)}\n- **Supporting signals:** {', '.join(lead.source_signals) or 'none'}\n- **Manual validation steps:**\n"
            + "\n".join(f"  - {redact_text(x)}" for x in lead.manual_validation_steps)
            + "\n- **Evidence to collect:**\n"
            + "\n".join(
                f"  - {redact_text(x)}" for x in lead.suggested_evidence_to_collect
            )
            + f"\n- **Related artifacts:** {', '.join(lead.related_evidence) or 'none'}"
        )
        _ = signals
    return "\n\n".join(chunks)


def render_markdown(project: ProjectCorrelationInventory) -> str:
    ready = [
        x for x in project.triage_leads if x.reportability == Reportability.REPORT_READY
    ]
    gaps = [
        x
        for x in project.triage_leads
        if x.reportability == Reportability.NEEDS_MORE_EVIDENCE
    ]
    noise = [
        x for x in project.triage_leads if x.reportability == Reportability.LIKELY_NOISE
    ]

    def rows(items: list[TriageLead]) -> str:
        return (
            "\n".join(
                f"- **{x.priority.value}** — {redact_text(x.title)} ({x.reportability.value})"
                for x in items
            )
            or "- _None._"
        )

    return redact_text(f"""# Project Correlation Report

## Summary

Artifacts: {len(project.artifacts)}; assets: {len(project.assets)}; signals: {len(project.signals)}; leads: {len(project.triage_leads)}.

## Artifacts analyzed

{chr(10).join(f"- `{x.artifact_type.value}` — `{x.path}` — {'parsed' if x.parsed else 'parse error'}" for x in project.artifacts) or "- _None._"}

## Correlated assets

{chr(10).join(f"- `{x.method} {x.host}{x.normalized_path}` — score {x.risk_score}" for x in project.assets) or "- _None._"}

## Risk signals

{chr(10).join(f"- **{x.severity.value}** — {x.title}" for x in project.signals) or "- _None._"}

## Top triage leads

{rows(project.triage_leads[:10])}

## Report-ready candidates

{rows(ready)}

## Leads needing more evidence

{rows(gaps)}

## Likely noise / low-value items

{rows(noise)}

## Manual validation checklist

{render_checklist(project)}

## Evidence gaps

Confirm affected assets, expected versus actual behavior, impact, redacted proof, reproduction notes, and severity rationale before submission.

## Redaction notice

Free-text evidence is redacted by default. Raw secrets, cookies, tokens, JWTs, authentication headers, and PII are not exported.

## Limitations

This is passive local correlation, not proof of vulnerability. It sends no requests, replays no traffic, generates no payloads, and performs no exploitation.
""")
