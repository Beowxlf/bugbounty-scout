# Synthetic end-to-end workflow

## Simple orchestrated path

```bash
bbs workflow init demo-target
# Copy local artifacts into demo-target/inputs/
bbs workflow detect demo-target
bbs workflow run demo-target
bbs workflow status demo-target
bbs workflow report demo-target --format markdown
```

This path only reads local files, redacts generated reports by default, and does
not send or replay requests.

## Advanced manual path

## Final report packaging

After manually validating a lead and collecting redacted evidence:

```bash
bbs submit from-evidence evidence/workspace.yml
bbs submit lint report-title-submission.yml
bbs submit preview report-title-submission.yml
bbs submit package report-title-submission.yml --platform generic
```

Review program rules and the generated checklist manually. BugBountyScout never
auto-submits the package.

Run individual analyzer commands when you need fine-grained control, then add
their saved inventories to a correlation project with `bbs correlate`.

This walkthrough uses only local synthetic fixtures. It makes no live requests,
replays no traffic, validates no credentials, and generates no exploit payloads.

1. **Create a workspace:** `bbs init demo-workbench`
2. **Load scope:** `cd demo-workbench && bbs scope init`; replace the template
   only with authorized lab rules, or use `../fixtures/fake_scope.yml`.
3. **Analyze HAR:** `bbs har report ../fixtures/fake.har --format json --output outputs/har.json`
4. **Map endpoints:** `bbs endpoints report ../fixtures/endpoints/simple_api.har --format json > outputs/endpoints.json`
5. **Analyze frontend:** `bbs frontend report ../fixtures/frontend/fake_frontend.js --format json > outputs/frontend.json`
6. **Analyze auth surface:** `bbs auth-surface report ../fixtures/auth_surface/fake_auth.har --format json > outputs/auth-surface.json`
7. **Analyze GraphQL:** `bbs graphql report ../fixtures/graphql/fake_graphql.har --format json > outputs/graphql.json`
8. **Build vocabulary:** `bbs paramforge report ../fixtures/paramforge/fake_api.har --format json > outputs/paramforge.json`
9. **Model authorization manually:** `bbs authz report ../fixtures/authz/fake_authz_matrix.yml --format json > outputs/authz.json`
10. **Store evidence:** `bbs evidence export ../fixtures/evidence/fake_workspace.yml --format markdown`
11. **Correlate artifacts:** `bbs correlate scan ../fixtures/correlate/fake_project_folder --output correlation-project.yml`
12. **Export report/checklist:** `bbs correlate report correlation-project.yml --format markdown` and `bbs correlate checklist correlation-project.yml --format markdown`.

For a self-contained generated project, run `bbs demo init synthetic-demo` and
follow `synthetic-demo/workflow.md`. All review leads are hypotheses for
authorized manual validation, not confirmed vulnerabilities.
