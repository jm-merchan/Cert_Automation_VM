#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/../app"
export VAULT_SKIP_VERIFY="${VAULT_SKIP_VERIFY:-true}"
python3 server.py