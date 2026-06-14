"""Passive, local-only target vocabulary extraction and safe wordlist export."""

import csv
import io
import json
import math
import re
from collections import Counter
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import yaml

from bugbounty_scout.models import (
    VocabularyInventory,
    VocabularyTerm,
    WordlistExport,
)
from bugbounty_scout.redaction import redact_text

SUPPORTED_SUFFIXES = {
    ".har",
    ".js",
    ".html",
    ".htm",
    ".json",
    ".txt",
    ".map",
    ".yml",
    ".yaml",
}
STOPWORDS = {
    "the",
    "and",
    "or",
    "true",
    "false",
    "null",
    "undefined",
    "div",
    "span",
    "class",
    "style",
    "script",
    "function",
    "return",
    "const",
    "let",
    "var",
    "http",
    "https",
    "www",
    "com",
    "net",
    "org",
    "js",
    "css",
    "html",
    "htm",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "svg",
    "map",
    "woff",
    "woff2",
}
RISK_WORDS = {
    "admin": 30,
    "debug": 25,
    "internal": 25,
    "role": 22,
    "permission": 25,
    "tenant": 25,
    "organization": 22,
    "org": 18,
    "invoice": 22,
    "billing": 25,
    "payment": 25,
    "export": 20,
    "upload": 20,
    "file": 15,
    "callback": 18,
    "redirect": 18,
    "token": 25,
    "session": 25,
    "auth": 25,
    "password": 30,
    "reset": 20,
    "invite": 20,
    "user": 12,
    "account": 15,
    "owner": 18,
    "member": 15,
}
TAG_WORDS = {
    "auth": ("auth", "token", "password", "login", "oauth"),
    "admin": ("admin",),
    "billing": ("billing", "invoice", "payment"),
    "file": ("file", "document"),
    "upload": ("upload",),
    "export": ("export",),
    "debug": ("debug",),
    "internal": ("internal",),
    "idor": ("id", "owner", "object"),
    "bola": ("object", "account", "user"),
    "graphql": ("graphql",),
    "storage": ("storage", "localstorage", "sessionstorage"),
    "role": ("role",),
    "permission": ("permission",),
    "tenant": ("tenant",),
    "organization": ("organization", "org"),
    "user": ("user",),
    "account": ("account",),
    "session": ("session",),
    "redirect": ("redirect",),
    "callback": ("callback",),
    "search": ("search", "query"),
}
SENSITIVE_VALUE_RE = re.compile(
    r"(?i)(bearer\s+\S+|eyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]{5,}|"
    r"(?:secret|password|token|api[_-]?key|session(?:id)?)\s*[=:]\s*\S+)"
)
PATH_RE = re.compile(r"""(?:https?://[^\s"'<>]+)?(/[A-Za-z0-9_./{}:-]+)""")
IDENT_RE = re.compile(r"\b[A-Za-z_$][A-Za-z0-9_$]{2,}\b")
PROP_RE = re.compile(r"""(?:["']([A-Za-z][\w.-]{1,})["']\s*:|\.([A-Za-z_$][\w$]*))""")
FORM_RE = re.compile(
    r"""<(?:input|select|textarea)[^>]+(?:name|id)=["']([^"']+)""", re.I
)
GRAPHQL_OPERATION_RE = re.compile(r"\b(query|mutation|subscription)\s+([A-Za-z_]\w*)")
GRAPHQL_VARIABLE_RE = re.compile(r"\$([A-Za-z_]\w*)")
HEADER_RE = re.compile(
    r"\b(?:X-[A-Za-z0-9-]+|Authorization|Content-Type|Accept-Language|X-CSRF-Token)\b",
    re.I,
)
COOKIE_RE = re.compile(
    r"(?:document\.cookie\s*=|cookie\s*[:=])\s*['\"]?([A-Za-z_][\w-]*)", re.I
)
STORAGE_RE = re.compile(
    r"(?:localStorage|sessionStorage)\.(?:getItem|setItem)\(\s*['\"]([^'\"]+)"
)


def normalize_term(value: str) -> str:
    value = unquote(str(value)).strip().strip("\"'`")
    value = re.sub(r"\s+", " ", value)
    return value.lower()


def split_term(value: str) -> list[str]:
    clean = unquote(str(value)).strip().strip("\"'`")
    camel = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", clean)
    return [part.lower() for part in re.split(r"[/_.\-\s:{}[\]()]+", camel) if part]


def is_useful(value: str) -> bool:
    normalized = normalize_term(value)
    return bool(
        normalized
        and normalized not in STOPWORDS
        and len(normalized) > 1
        and len(normalized) <= 180
        and not normalized.isdigit()
        and not SENSITIVE_VALUE_RE.search(normalized)
        and not normalized.startswith("<redacted-")
    )


def safe_mutations(value: str) -> list[str]:
    words = split_term(value)
    if not words:
        return []
    variants = {
        "".join([words[0], *[word.title() for word in words[1:]]]),
        "_".join(words),
        "-".join(words),
        "".join(words).lower(),
        "".join(words).upper(),
    }
    base = "".join([words[0], *[word.title() for word in words[1:]]])
    if base.endswith("s") and len(base) > 3:
        variants.add(base[:-1])
    else:
        variants.add(base + "s")
    return sorted(item for item in variants if is_useful(item))


def risk_score(value: str) -> int:
    lowered = normalize_term(value)
    score = sum(weight for word, weight in RISK_WORDS.items() if word in lowered)
    return min(100, score)


def tags_for(value: str, category: str = "") -> list[str]:
    lowered = normalize_term(value)
    tags = {
        tag
        for tag, words in TAG_WORDS.items()
        if any(word in lowered for word in words)
    }
    if category.startswith("graphql"):
        tags.add("graphql")
    if category == "object_name" or lowered.endswith("id"):
        tags.update({"idor", "bola"})
    return sorted(tags)


def _category_for(value: str, default: str) -> str:
    lowered = normalize_term(value)
    groups = (
        ("admin_term", ("admin",)),
        ("billing_term", ("billing", "invoice", "payment")),
        ("file_term", ("file", "upload", "document", "export")),
        ("organization_term", ("organization", "tenant", "orgid")),
        ("role_permission_term", ("role", "permission", "owner", "member")),
        ("debug_term", ("debug", "internal", "trace", "stack")),
        ("auth_term", ("auth", "token", "session", "password", "login", "reset")),
    )
    for category, words in groups:
        if any(word in lowered for word in words):
            return category
    return default


class _Collector:
    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict[str, Any]] = {}
        self.sources: set[str] = set()

    def add(
        self,
        value: Any,
        category: str,
        source: Path,
        source_type: str,
        context: str = "",
        evidence: str = "",
        *,
        classify: bool = False,
    ) -> None:
        raw = str(value).strip()
        if not is_useful(raw):
            return
        category = _category_for(raw, category) if classify else category
        normalized = normalize_term(raw)
        key = (normalized, category)
        item = self.items.setdefault(
            key,
            {
                "value": raw,
                "normalized_value": normalized,
                "category": category,
                "source_type": source_type,
                "source_file": str(source),
                "context": context,
                "occurrences": 0,
                "evidence": "",
            },
        )
        item["occurrences"] += 1
        if evidence and not item["evidence"]:
            item["evidence"] = redact_text(evidence)[:500]
        self.sources.add(str(source))

    def add_parts(
        self, value: str, source: Path, source_type: str, context: str
    ) -> None:
        for part in split_term(value):
            self.add(part, "route_segment", source, source_type, context, classify=True)

    def finish(
        self, project_name: str = "BugBountyScout ParamForge inventory"
    ) -> VocabularyInventory:
        terms = []
        for item in self.items.values():
            count = item["occurrences"]
            redacted = redact_text(item["evidence"])
            model_data = {
                key: value for key, value in item.items() if key != "evidence"
            }
            terms.append(
                VocabularyTerm(
                    id="vocab-"
                    + sha256(
                        f"{item['normalized_value']}|{item['category']}".encode()
                    ).hexdigest()[:12],
                    **model_data,
                    frequency_score=min(100, round(20 * math.log2(count + 1))),
                    risk_score=risk_score(item["value"]),
                    tags=tags_for(item["value"], item["category"]),
                    evidence="",
                    redacted_evidence=redacted,
                )
            )
        terms.sort(
            key=lambda term: (
                -term.risk_score,
                -term.occurrences,
                term.normalized_value,
            )
        )
        categories = Counter(term.category.value for term in terms)
        return VocabularyInventory(
            project_name=project_name,
            terms=terms,
            categories=dict(sorted(categories.items())),
            source_files=sorted(self.sources),
            summary={
                "terms": len(terms),
                "occurrences": sum(term.occurrences for term in terms),
                "sources_analyzed": len(self.sources),
                "passive_only": True,
                "redacted_by_default": True,
            },
        )


def _walk_json(value: Any, collector: _Collector, source: Path, category: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            collector.add(key, category, source, "json", "JSON key", classify=True)
            _walk_json(child, collector, source, category)
    elif isinstance(value, list):
        for child in value:
            _walk_json(child, collector, source, category)


def _scan_har(path: Path, collector: _Collector) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("log", {}).get("entries")
    if not isinstance(entries, list):
        raise ValueError("HAR must contain a log.entries list")
    for entry in entries:
        request = entry.get("request", {})
        response = entry.get("response", {})
        url = str(request.get("url", ""))
        parsed = urlsplit(url)
        collector.add(parsed.path or "/", "endpoint_path", path, "har", "request URL")
        collector.add_parts(parsed.path, path, "har", "request route")
        for item in request.get("queryString", []):
            collector.add(item.get("name", ""), "query_param", path, "har", "query")
        for side, container in (("request", request), ("response", response)):
            for header in container.get("headers", []):
                collector.add(
                    header.get("name", ""), "header_name", path, "har", f"{side} header"
                )
            for cookie in container.get("cookies", []):
                collector.add(
                    cookie.get("name", ""), "cookie_name", path, "har", f"{side} cookie"
                )
        post = request.get("postData", {})
        for param in post.get("params", []) if isinstance(post, dict) else []:
            collector.add(
                param.get("name", ""), "body_param", path, "har", "request body"
            )
        for container, category in (
            (post, "json_key"),
            (response.get("content", {}), "response_key"),
        ):
            text = container.get("text", "") if isinstance(container, dict) else ""
            if text:
                try:
                    parsed_json = json.loads(text)
                except (json.JSONDecodeError, TypeError):
                    parsed_json = None
                if parsed_json is not None:
                    _walk_json(parsed_json, collector, path, category)
                    _scan_graphql_value(parsed_json, collector, path, "har")


def _scan_graphql_value(
    value: Any, collector: _Collector, source: Path, source_type: str
) -> None:
    if isinstance(value, dict):
        query = value.get("query")
        if isinstance(query, str):
            _scan_graphql_text(query, collector, source, source_type)
        variables = value.get("variables")
        if isinstance(variables, dict):
            for key in variables:
                collector.add(
                    key, "graphql_variable", source, source_type, "GraphQL variables"
                )
        operation = value.get("operationName")
        if isinstance(operation, str):
            collector.add(
                operation, "graphql_operation", source, source_type, "GraphQL operation"
            )
        for child in value.values():
            _scan_graphql_value(child, collector, source, source_type)
    elif isinstance(value, list):
        for child in value:
            _scan_graphql_value(child, collector, source, source_type)


def _scan_graphql_text(
    text: str, collector: _Collector, source: Path, source_type: str
) -> None:
    for match in GRAPHQL_OPERATION_RE.finditer(text):
        collector.add(
            match.group(2),
            "graphql_operation",
            source,
            source_type,
            "GraphQL operation",
        )
    for match in GRAPHQL_VARIABLE_RE.finditer(text):
        collector.add(
            match.group(1), "graphql_variable", source, source_type, "GraphQL variable"
        )


def _scan_text(path: Path, text: str, collector: _Collector) -> None:
    source_type = path.suffix.lower().lstrip(".") or "text"
    for match in PATH_RE.finditer(text):
        route = match.group(1).rstrip(".,;)")
        collector.add(route, "endpoint_path", path, source_type, "path")
        collector.add_parts(route, path, source_type, "path segment")
    for match in FORM_RE.finditer(text):
        collector.add(
            match.group(1), "form_field", path, source_type, "HTML form field"
        )
    for match in PROP_RE.finditer(text):
        collector.add(
            next(group for group in match.groups() if group),
            "json_key",
            path,
            source_type,
            "object property",
            classify=True,
        )
    for match in HEADER_RE.finditer(text):
        collector.add(
            match.group(0), "header_name", path, source_type, "header-like name"
        )
    for match in COOKIE_RE.finditer(text):
        collector.add(
            match.group(1), "cookie_name", path, source_type, "cookie-like name"
        )
    for match in STORAGE_RE.finditer(text):
        collector.add(
            match.group(1),
            "object_name",
            path,
            source_type,
            "browser storage key",
            classify=True,
        )
    _scan_graphql_text(text, collector, path, source_type)
    for match in IDENT_RE.finditer(text):
        collector.add(
            match.group(0),
            "javascript_identifier",
            path,
            source_type,
            "identifier",
            classify=True,
        )


def _scan_inventory_data(
    data: dict[str, Any], path: Path, collector: _Collector
) -> None:
    if "endpoints" in data:
        for endpoint in data.get("endpoints", []):
            for field in ("path", "normalized_path"):
                value = endpoint.get(field, "")
                collector.add(value, "endpoint_path", path, "endpoint_inventory", field)
                collector.add_parts(value, path, "endpoint_inventory", field)
            for field, category in (
                ("query_params", "query_param"),
                ("body_params", "body_param"),
                ("json_keys", "json_key"),
                ("header_names", "header_name"),
                ("object_id_candidates", "object_name"),
                ("risk_tags", "unknown"),
            ):
                for value in endpoint.get(field, []):
                    collector.add(
                        value,
                        category,
                        path,
                        "endpoint_inventory",
                        field,
                        classify=field == "risk_tags",
                    )
    if "runtime_configs" in data or "storage_references" in data:
        for finding in data.get("runtime_configs", []) + data.get("api_clients", []):
            context = finding.get("context", {})
            for key in context:
                collector.add(
                    key,
                    "json_key",
                    path,
                    "frontend_inventory",
                    "runtime config key",
                    classify=True,
                )
            collector.add(
                finding.get("title", ""),
                "object_name",
                path,
                "frontend_inventory",
                "finding title",
                classify=True,
            )
        for route in data.get("routes", []):
            collector.add(
                route.get("path", ""),
                "endpoint_path",
                path,
                "frontend_inventory",
                "route",
            )
            collector.add_parts(
                route.get("path", ""), path, "frontend_inventory", "route"
            )
        for storage in data.get("storage_references", []):
            collector.add(
                storage.get("key", ""),
                "object_name",
                path,
                "frontend_inventory",
                "storage key",
                classify=True,
            )
    if "actors" in data and "objects" in data:
        for actor in data.get("actors", []):
            collector.add(
                actor.get("role", ""),
                "role_permission_term",
                path,
                "authz_matrix",
                "actor role",
            )
        for obj in data.get("objects", []):
            collector.add(
                obj.get("object_type", ""),
                "object_name",
                path,
                "authz_matrix",
                "object type",
                classify=True,
            )
            for key in obj.get("identifiers", {}):
                collector.add(
                    key, "object_name", path, "authz_matrix", "identifier key"
                )
        for endpoint in data.get("endpoint_templates", []):
            collector.add(
                endpoint.get("path_template", ""),
                "endpoint_path",
                path,
                "authz_matrix",
                "endpoint template",
            )
            collector.add_parts(
                endpoint.get("path_template", ""),
                path,
                "authz_matrix",
                "template segment",
            )
            for value in endpoint.get("object_id_candidates", []) + endpoint.get(
                "risk_tags", []
            ):
                collector.add(
                    value,
                    "object_name",
                    path,
                    "authz_matrix",
                    "authz vocabulary",
                    classify=True,
                )
        for rule in data.get("expected_access", []):
            collector.add(
                rule.get("boundary_type", ""),
                "organization_term",
                path,
                "authz_matrix",
                "boundary type",
                classify=True,
            )
    if "evidence_items" in data and "reproduction_steps" in data:
        for asset in data.get("affected_assets", []):
            parsed = urlsplit(asset)
            collector.add_parts(
                parsed.path or asset, path, "evidence_workspace", "affected asset"
            )
        for field in ("title", "finding_type"):
            collector.add(
                data.get(field, ""),
                "object_name",
                path,
                "evidence_workspace",
                field,
                classify=True,
            )
        for tag in data.get("tags", []):
            collector.add(
                tag, "unknown", path, "evidence_workspace", "tag", classify=True
            )
        for item in data.get("evidence_items", []):
            collector.add(
                item.get("title", ""),
                "object_name",
                path,
                "evidence_workspace",
                "evidence title",
                classify=True,
            )
            _scan_text(
                path, redact_text(item.get("redacted_evidence_text", "")), collector
            )
        for step in data.get("reproduction_steps", []):
            _scan_text(path, redact_text(step.get("action", "")), collector)


def scan_file(path: Path) -> VocabularyInventory:
    if not path.is_file():
        raise ValueError(f"Input file does not exist: {path}")
    if path.suffix.lower() not in SUPPORTED_SUFFIXES:
        raise ValueError(f"Unsupported input type: {path.suffix or '<none>'}")
    collector = _Collector()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"Could not read input file {path}: {exc}") from exc
    if path.suffix.lower() == ".har":
        try:
            _scan_har(path, collector)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in HAR file {path}: {exc}") from exc
    elif path.suffix.lower() in {".json", ".map", ".yml", ".yaml"}:
        if not text.strip():
            collector.sources.add(str(path))
            return collector.finish()
        try:
            data = (
                json.loads(text)
                if path.suffix.lower() in {".json", ".map"}
                else yaml.safe_load(text)
            )
        except (json.JSONDecodeError, yaml.YAMLError) as exc:
            raise ValueError(f"Invalid structured file {path}: {exc}") from exc
        if isinstance(data, dict):
            _scan_inventory_data(data, path, collector)
            _walk_json(data, collector, path, "json_key")
            _scan_graphql_value(data, collector, path, path.suffix.lower().lstrip("."))
        _scan_text(path, text, collector)
    else:
        _scan_text(path, text, collector)
    collector.sources.add(str(path))
    return collector.finish()


def scan_folder(path: Path) -> VocabularyInventory:
    if not path.is_dir():
        raise ValueError(f"Input folder does not exist: {path}")
    collector = _Collector()
    files = sorted(
        item
        for item in path.rglob("*")
        if item.is_file() and item.suffix.lower() in SUPPORTED_SUFFIXES
    )
    for item in files:
        inventory = scan_file(item)
        for term in inventory.terms:
            for _ in range(term.occurrences):
                collector.add(
                    term.value,
                    term.category.value,
                    item,
                    term.source_type,
                    term.context,
                    term.redacted_evidence,
                )
        collector.sources.add(str(item))
    return collector.finish()


def load_or_scan(path: Path) -> VocabularyInventory:
    if path.is_dir():
        return scan_folder(path)
    if path.suffix.lower() == ".json":
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "terms" in data and "categories" in data:
                return VocabularyInventory.model_validate(data)
        except (OSError, json.JSONDecodeError, ValueError):
            pass
    return scan_file(path)


EXPORT_CATEGORIES = {
    "all": None,
    "params": {"query_param", "body_param", "form_field"},
    "query_params": {"query_param"},
    "body_params": {"body_param"},
    "json_keys": {"json_key", "response_key"},
    "headers": {"header_name"},
    "cookies": {"cookie_name"},
    "routes": {"route_segment"},
    "endpoints": {"endpoint_path"},
    "object_ids": {"object_name"},
    "graphql": {"graphql_variable", "graphql_operation"},
    "admin": {"admin_term"},
    "billing": {"billing_term"},
    "file": {"file_term"},
    "auth": {"auth_term"},
    "debug": {"debug_term"},
}


def select_terms(
    inventory: VocabularyInventory, category: str, mutations: bool = False
) -> list[str]:
    allowed = EXPORT_CATEGORIES.get(category)
    selected = []
    for term in inventory.terms:
        matches = (
            (allowed is None and category == "all")
            or (bool(allowed) and term.category.value in allowed)
            or (category in {"idor", "storage"} and category in term.tags)
            or category == term.category.value
        )
        if matches:
            selected.append(term.value)
    if mutations:
        selected.extend(
            mutation for value in selected for mutation in safe_mutations(value)
        )
    return sorted({normalize_term(value) for value in selected if is_useful(value)})


def render_markdown(inventory: VocabularyInventory) -> str:
    def section(title: str, terms: list[VocabularyTerm]) -> str:
        rows = "\n".join(
            f"- `{term.value}` — occurrences {term.occurrences}, "
            f"risk {term.risk_score}, tags: {', '.join(term.tags) or 'none'}"
            for term in terms[:25]
        )
        return f"## {title}\n\n{rows or '_None found._'}\n"

    def by_category(names: set[str]) -> list[VocabularyTerm]:
        return [term for term in inventory.terms if term.category.value in names]

    frequency = sorted(
        inventory.terms, key=lambda term: (-term.occurrences, term.normalized_value)
    )
    risk = sorted(
        inventory.terms, key=lambda term: (-term.risk_score, -term.occurrences)
    )
    return (
        "# ParamForge Passive Vocabulary Report\n\n"
        "## Summary\n\n"
        f"- Terms: {len(inventory.terms)}\n- Sources: {len(inventory.source_files)}\n"
        "- Mode: passive, local-only\n\n"
        "## Sources analyzed\n\n"
        + ("\n".join(f"- `{source}`" for source in inventory.source_files) or "_None._")
        + "\n\n"
        + section("Top terms by frequency", frequency)
        + section("Top terms by risk", risk)
        + section(
            "Parameters", by_category({"query_param", "body_param", "form_field"})
        )
        + section("JSON/body keys", by_category({"json_key", "response_key"}))
        + section("Headers", by_category({"header_name"}))
        + section("Cookies", by_category({"cookie_name"}))
        + section("Route segments", by_category({"route_segment"}))
        + section("Endpoint paths", by_category({"endpoint_path"}))
        + section("Object/ID terms", by_category({"object_name"}))
        + section(
            "GraphQL terms", by_category({"graphql_variable", "graphql_operation"})
        )
        + section(
            "Auth/admin/billing/file terms",
            by_category({"auth_term", "admin_term", "billing_term", "file_term"}),
        )
        + "## Suggested manual uses\n\n"
        "Use names as review aids for authorized endpoint analysis, API "
        "documentation, authorization matrices, and manually configured "
        "wordlists.\n\n"
        "## Redaction notice\n\n"
        "Secret values, cookies, JWTs, authorization values, session identifiers, "
        "and obvious credentials are excluded or redacted. Exports contain names "
        "and terms only.\n\n"
        "## Limitations\n\n"
        "Heuristic extraction can produce false positives and does not prove that "
        "a parameter or route exists. ParamForge sends no requests, replays "
        "nothing, fuzzes nothing, and generates no attack payloads.\n"
    )


def render_json(inventory: VocabularyInventory) -> str:
    return inventory.model_dump_json(indent=2)


def export_wordlist(
    inventory: VocabularyInventory, category: str, output_format: str
) -> str:
    terms = select_terms(inventory, category)
    export = WordlistExport(
        name=f"paramforge-{category}",
        category=category,
        terms=terms,
        output_format=output_format,
    )
    if output_format == "txt":
        return "".join(f"{term}\n" for term in terms)
    if output_format == "json":
        return export.model_dump_json(indent=2) + "\n"
    if output_format == "csv":
        stream = io.StringIO()
        writer = csv.writer(stream)
        writer.writerow(["term", "category"])
        writer.writerows((term, category) for term in terms)
        return stream.getvalue()
    raise ValueError(f"Unsupported export format: {output_format}")


def export_all(inventory: VocabularyInventory, output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    mapping = {
        "params.txt": "params",
        "json_keys.txt": "json_keys",
        "headers.txt": "headers",
        "cookies.txt": "cookies",
        "routes.txt": "routes",
        "endpoints.txt": "endpoints",
        "object_ids.txt": "object_ids",
        "graphql.txt": "graphql",
        "admin.txt": "admin",
        "billing.txt": "billing",
        "file.txt": "file",
        "auth.txt": "auth",
        "debug.txt": "debug",
        "all_terms.txt": "all",
    }
    paths = []
    for name, category in mapping.items():
        output = output_dir / name
        output.write_text(export_wordlist(inventory, category, "txt"), encoding="utf-8")
        paths.append(output)
    return paths
