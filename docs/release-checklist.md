# Release checklist

BugBountyScout releases remain local-first, passive/manual-first, redacted by
default, and restricted to authorized assets, owned systems, and labs.

## Metadata and documentation

- [ ] Bump the version in `pyproject.toml` and `bugbounty_scout.__version__`.
- [ ] Add a truthful `CHANGELOG.md` entry.
- [ ] Verify project name, description, Python classifiers, dependencies,
  Hatchling wheel package, and `bbs` entry point.
- [ ] Review README, command reference, example workflow, safety documentation,
  and all changed module guides.
- [ ] Confirm no new live request, replay, exploit, fuzzing, bypass, cloud, or
  telemetry behavior was introduced.

## Validation

- Run `bbs submit --help`.
- Lint `fixtures/submit/fake_draft.yml`.
- Export the fixture as Markdown and JSON.
- Build a temporary local package and verify its manifest and checklist.
- Confirm redaction warnings never print detected secret values.

- Smoke-test `bbs workflow init`, `detect`, `run`, `status`, and `report`.

- [ ] Create a clean Python 3.11, 3.12, and 3.13 environment.
- [ ] Run `bash scripts/test_bench_validation.sh`.
- [ ] Run `bash scripts/smoke_py_path.sh` as the restricted-network fallback.
- [ ] Validate every JSON, HAR, and source-map fixture with `python -m json.tool`.
- [ ] Confirm fixtures use synthetic values and reserved `.test` domains.
- [ ] Inspect Markdown and JSON exports for raw tokens, cookies, keys, PII,
  session identifiers, and authorization headers.
- [ ] Run `bbs --help`, each command-group help, `bbs doctor`, and demo
  init/status/clean.
- [ ] Confirm GitHub Actions passes lint, format, compile, tests, fixtures,
  installed CLI help, doctor, and fallback smoke checks.

## Restricted network troubleshooting

Some managed environments return `403 Forbidden` while pip resolves Hatchling
from their configured package proxy. That is an environment/index failure, not
evidence that Hatchling or project metadata is broken. Record the exact pip
error, do not claim editable installation or `bbs` validation passed, and run
the PYTHONPATH smoke script. A release still requires a successful clean
installed-package validation in CI or another unrestricted test environment.

## Do not release when

- pytest fails.
- Ruff check or Ruff format check fails.
- compileall fails.
- Any fixture JSON/HAR/source map is invalid.
- Redaction tests fail or reports expose raw tokens/secrets.
- CLI help, doctor, or demo init fails.
- Packaging metadata, wheel construction, dependencies, or console entry point
  is broken.
- Safety language is absent, misleading, or contradicted by behavior.
- GitHub Actions is failing or has not run.
