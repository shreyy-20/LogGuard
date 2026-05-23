#!/usr/bin/env bash
set -e

export DB_PATH="${DB_PATH:-data/logguard.db}"
export LOGS_DIR="${LOGS_DIR:-logs}"

mkdir -p "$(dirname "$DB_PATH")"
mkdir -p "$LOGS_DIR"

# Render containers do not expose host Linux logs, so demo deploys can generate
# synthetic traffic for the dashboard to ingest.
if [ "${DEMO_LOGS:-true}" = "true" ]; then
  python scripts/generate_mock_logs.py &
fi

# Start LogGuard daemon in background first.
python -m src.main &

# Then start FastAPI web console using Uvicorn on the Render-assigned port.
exec uvicorn src.web.app:app --host 0.0.0.0 --port "${PORT:-8000}" --workers "${WEB_CONCURRENCY:-1}"
