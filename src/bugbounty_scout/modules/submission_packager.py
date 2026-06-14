"""Build local ReportForge package directories without external submission."""

import json
import shutil
from pathlib import Path

from bugbounty_scout.models import PlatformProfile, SubmissionDraft, SubmissionPackage
from bugbounty_scout.modules.reportforge import (
    checklist,
    lint_draft,
    render_checklist,
    render_json,
    render_markdown,
)

MAX_ATTACHMENT_BYTES = 10_000_000


def build_package(
    draft: SubmissionDraft,
    output: Path,
    profile: PlatformProfile | str,
) -> SubmissionPackage:
    profile = PlatformProfile(profile)
    output.mkdir(parents=True, exist_ok=True)
    attachments_dir = output / "attachments"
    attachments_dir.mkdir(exist_ok=True)
    blocking, warnings = lint_draft(draft)
    copied = []
    for item in draft.attachments:
        source = Path(item.path)
        if not item.include_in_package or not source.is_file():
            continue
        if source.stat().st_size > MAX_ATTACHMENT_BYTES:
            warnings.append(f"Large attachment was not copied: {item.title}")
            continue
        destination = attachments_dir / source.name
        shutil.copy2(source, destination)
        copy = item.model_copy(update={"path": str(destination)})
        copied.append(copy)
    markdown, structured = render_markdown(draft, profile), render_json(draft)
    (output / "report.md").write_text(markdown, encoding="utf-8")
    (output / "report.json").write_text(structured, encoding="utf-8")
    manifest = [item.model_dump(mode="json") for item in draft.attachments]
    (output / "attachment-manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    (output / "checklist.md").write_text(
        render_checklist(draft, "markdown"), encoding="utf-8"
    )
    (output / "quality-warnings.json").write_text(
        json.dumps({"blocking": blocking, "warnings": warnings}, indent=2),
        encoding="utf-8",
    )
    (output / "README.md").write_text(
        "# Local submission package\n\n"
        "Manually review scope, program rules, redaction, evidence, and every claim. "
        "This package is not submitted automatically.\n",
        encoding="utf-8",
    )
    return SubmissionPackage(
        id=f"package-{draft.id}",
        title=draft.title,
        platform_profile=profile,
        source_type=draft.source_type,
        source_file=draft.source_file,
        output_dir=str(output),
        report_markdown=str(output / "report.md"),
        report_json=str(output / "report.json"),
        attachments=copied,
        attachment_manifest=str(output / "attachment-manifest.json"),
        quality_warnings=blocking + warnings,
        redaction_warnings=draft.redaction_warnings,
        final_checklist=checklist(draft),
        status=draft.status,
    )
