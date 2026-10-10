#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$ROOT"
. .venv/bin/activate
exec gunicorn --bind "${CYBERSHIELD_BIND:-127.0.0.1:5000}" --workers "${CYBERSHIELD_WORKERS:-2}" --timeout 120 app:app
