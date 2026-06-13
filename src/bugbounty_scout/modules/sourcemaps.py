"""Local source-map discovery and passive parsing."""

import json
import re
from hashlib import sha256
from pathlib import Path

from bugbounty_scout.models import SourceMapFinding
from bugbounty_scout.redaction import redact_text

REFERENCE_RE = re.compile(r"sourceMappingURL\s*=\s*([^\s*]+)")
COMMENT_RE = re.compile(
    r"(?i)(TODO\s+security|fix\s+auth|bypass|debug|admin|internal|secret|"
    r"temporary|do not expose|hardcoded|remove before production|FIXME|HACK)"
)


def _finding(
    path: Path, finding_type: str, evidence: str, **kwargs
) -> SourceMapFinding:
    key = f"{path}:{finding_type}:{evidence}:{kwargs.get('line')}"
    return SourceMapFinding(
        id=f"sm-{sha256(key.encode()).hexdigest()[:12]}",
        source_map_file=str(path),
        finding_type=finding_type,
        evidence="",
        redacted_evidence=redact_text(evidence.strip()),
        recommendation=(
            "Review exposed source context and remove production maps if unnecessary."
        ),
        **kwargs,
    )


def references(path: Path, text: str) -> list[SourceMapFinding]:
    return [
        _finding(
            path,
            "source-map-reference",
            match.group(0),
            referenced_by=str(path),
            original_source_path=match.group(1),
            line=text.count("\n", 0, match.start()) + 1,
        )
        for match in REFERENCE_RE.finditer(text)
    ]


def parse_source_map(
    path: Path,
) -> tuple[list[SourceMapFinding], list[tuple[str, str]]]:
    """Parse a local source map, returning observations and embedded sources."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"Could not read source map {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid source map JSON {path}: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("sources"), list):
        raise ValueError(f"Invalid source map structure: {path}")
    sources = [str(item) for item in data["sources"]]
    contents = data.get("sourcesContent")
    contents = contents if isinstance(contents, list) else []
    findings = [
        _finding(
            path,
            "source-map-exposure",
            f"sourceRoot={data.get('sourceRoot', '')}; sources={len(sources)}",
            original_source_path=source,
        )
        for source in sources
    ]
    embedded = []
    for index, source in enumerate(sources):
        content = (
            str(contents[index]) if index < len(contents) and contents[index] else ""
        )
        if content:
            embedded.append((source, content))
            for match in COMMENT_RE.finditer(content):
                findings.append(
                    _finding(
                        path,
                        "sensitive-comment",
                        match.group(0),
                        original_source_path=source,
                        line=content.count("\n", 0, match.start()) + 1,
                        severity="low",
                    )
                )
    return findings, embedded
