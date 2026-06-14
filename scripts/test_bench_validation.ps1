$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
ruff check .
ruff format --check .
python -m compileall -q src tests
python -m pytest
bbs --help
bbs doctor
bbs har summary fixtures/fake.har
bbs endpoints from-har fixtures/endpoints/simple_api.har
bbs frontend scan-file fixtures/frontend/fake_frontend.js
bbs auth-surface scan-har fixtures/auth_surface/fake_auth.har
bbs graphql scan-har fixtures/graphql/fake_graphql.har
bbs paramforge scan-har fixtures/paramforge/fake_api.har
bbs correlate scan fixtures/correlate/fake_project_folder
Remove-Item demo-validation -Recurse -Force -ErrorAction SilentlyContinue
bbs demo init demo-validation
bbs demo status demo-validation
bbs demo clean demo-validation
bbs workflow --help
Remove-Item testbench-workflow -Recurse -Force -ErrorAction SilentlyContinue
bbs workflow init testbench-workflow
bbs workflow detect testbench-workflow
bbs workflow status testbench-workflow
bbs workflow clean testbench-workflow
bbs submit --help
bbs submit lint fixtures/submit/fake_draft.yml
bbs submit export fixtures/submit/fake_draft.yml --format markdown
