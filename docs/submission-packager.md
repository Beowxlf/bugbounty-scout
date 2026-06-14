# ReportForge / Submission Packager

ReportForge converts existing local BugBountyScout artifacts into structured,
redacted drafts and local submission packages. It accepts Evidence Locker
workspaces, Project Correlator leads, Workflow Orchestrator workspaces, and
finding YAML/JSON files.

## Example workflow

```bash
bbs submit from-evidence evidence-workspace.yml
bbs submit lint user-a-invoice-submission.yml
bbs submit redact-check user-a-invoice-submission.yml
bbs submit preview user-a-invoice-submission.yml
bbs submit package user-a-invoice-submission.yml --platform hackerone
```

For correlator and workflow inputs:

```bash
bbs submit from-lead correlation-project.yml --lead-id lead-123
bbs submit from-workflow project-workspace/
```

Leads are not treated as proof. Missing impact, reproduction steps, affected
assets, or evidence block readiness and require manual work.

## Platform profiles

Local formatting profiles are available for generic, HackerOne-style,
Bugcrowd-style, Intigriti-style, YesWeHack-style, GitHub Security
Advisory-style, and internal reports. Profiles only arrange headings; they do
not connect to any platform or require credentials.

## Packages, warnings, and redaction

`bbs submit package` creates `report.md`, `report.json`, an `attachments/`
directory, `attachment-manifest.json`, `checklist.md`,
`quality-warnings.json`, and a package README. Missing files are not copied.
Files over 10 MB receive a conservative warning and are not copied.

Linting checks claim completeness, attachment existence, severity support, and
common sensitive-data patterns. Redaction checks report category names only,
not raw detected values. Email and phone detection can produce false positives;
binary attachments and screenshots still require visual manual review.

## What it does not do

ReportForge does not submit reports, authenticate to platforms, call APIs, send
live requests, replay traffic, validate secrets, generate payloads, fuzz,
scan, or automate exploitation. Manual submission keeps program-rule,
authorization, accuracy, and disclosure decisions with the researcher.

Always confirm scope and program rules manually, reproduce only with authorized
test data, redact screenshots, verify every claim, and review every generated
file before sharing.
