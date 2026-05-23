#!/usr/bin/env bash
set -e

mkdir -p "$(dirname "${DB_PATH:-/app/data/logguard.db}")"
mkdir -p "${LOGS_DIR:-/app/logs}"

# Render containers do not expose host Linux logs, so demo deploys can generate
# synthetic traffic for the dashboard to ingest.
if [ "${DEMO_LOGS:-false}" = "true" ]; then
  python scripts/generate_mock_logs.py &
fi

# Start LogGuard daemon in background first.
python -m src.main &

# Then start FastAPI web console using Uvicorn on the Render-assigned port.
exec uvicorn src.web.app:app --host 0.0.0.0 --port "${PORT:-8000}" --workers 4
