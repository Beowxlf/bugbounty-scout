#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="${PYTHONPATH:+$PYTHONPATH:}src"

python -m bugbounty_scout.cli --help >/dev/null
python -m bugbounty_scout.cli doctor
python -m bugbounty_scout.cli har summary fixtures/fake.har >/dev/null
python -m bugbounty_scout.cli endpoints from-har fixtures/endpoints/simple_api.har >/dev/null
python -m bugbounty_scout.cli frontend scan-file fixtures/frontend/fake_frontend.js >/dev/null
python -m bugbounty_scout.cli auth-surface scan-har fixtures/auth_surface/fake_auth.har >/dev/null
python -m bugbounty_scout.cli graphql scan-har fixtures/graphql/fake_graphql.har >/dev/null
python -m bugbounty_scout.cli paramforge scan-har fixtures/paramforge/fake_api.har >/dev/null
python -m bugbounty_scout.cli correlate scan fixtures/correlate/fake_project_folder --output /tmp/bbs-smoke-correlation.yml >/dev/null
rm -f /tmp/bbs-smoke-correlation.yml
