# LogGuard

Production-style Linux log monitoring, threat detection, and analytics dashboard built with Python, FastAPI, SQLite, and Render.

[Live Demo](https://logguard-l31x.onrender.com) | [Architecture Guide](ARCHITECTURE.md) | [Deployment Guide](DEPLOYMENT.md)

> Demo note: the hosted Render deployment uses generated sample logs so the dashboard always has live-looking data. Alerts such as SSH brute-force attempts are simulated for demonstration and testing.

---

## Overview

LogGuard monitors Linux-style log files in real time, parses them into structured events, stores them in SQLite, detects suspicious patterns, and exposes the results through both a web dashboard and command-line tools.

It is designed as a complete observability/security project rather than a static UI mockup: the deployed app runs a background ingestion daemon, a FastAPI web service, a SQLite-backed analytics layer, and a demo traffic generator for the hosted environment.

## Live Deployment

The project is deployed on Render:

```text
https://logguard-l31x.onrender.com
```

The hosted dashboard includes simulated traffic for:

- Linux system logs
- SSH authentication failures
- Brute-force attack patterns
- Kernel/resource exhaustion events
- Application warnings and crashes

## Features

- Real-time file tailing for `syslog`, `auth.log`, `kern.log`, and custom application logs
- Log rotation and truncation handling
- Structured parsing for syslog, authentication, kernel, and custom formats
- SQLite storage with WAL mode and batched writes
- Full-text search with SQLite FTS5
- Security analysis for SSH brute force, repeated failures, crashes, OOM events, and critical keywords
- FastAPI web dashboard with log statistics, severity distribution, recent logs, and alert management
- CLI tools for search, stats, alerts, and export
- Render deployment with GitHub Actions triggered deploys

## Tech Stack

- Python 3.11+
- FastAPI
- Uvicorn
- SQLite
- Jinja2
- Rich
- Click
- Docker
- GitHub Actions
- Render

## Project Structure

```text
.
|-- .github/workflows/
|   |-- ci.yml
|   `-- deploy_render.yml
|-- config/
|   |-- config.yaml
|   `-- config.sample.env
|-- docker/
|   |-- Dockerfile
|   `-- docker-compose.yml
|-- scripts/
|   |-- generate_mock_logs.py
|   |-- get_render_service_ids.py
|   |-- render_start.sh
|   `-- setup.sh
|-- src/
|   |-- analyzer.py
|   |-- alerter.py
|   |-- config.py
|   |-- database.py
|   |-- main.py
|   |-- monitor.py
|   |-- parser.py
|   |-- cli/
|   `-- web/
|-- tests/
|-- ARCHITECTURE.md
|-- DEPLOYMENT.md
|-- README.md
|-- render.yaml
`-- requirements.txt
```

## Local Setup

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the demo log generator in one terminal:

```bash
python scripts/generate_mock_logs.py
```

Start the LogGuard daemon in a second terminal:

```bash
python -m src.main
```

Start the web dashboard in a third terminal:

```bash
python src/web/app.py
```

Open:

```text
http://localhost:8000
```

## CLI Usage

Search logs:

```bash
python -m src.cli.commands search --level CRITICAL
python -m src.cli.commands search --program sshd --limit 10
python -m src.cli.commands search --keyword "failed password"
```

View statistics:

```bash
python -m src.cli.commands stats
```

Review alerts:

```bash
python -m src.cli.commands alerts
python -m src.cli.commands alerts --unresolved
```

Export results:

```bash
python -m src.cli.commands export --format csv --output security_report.csv --level WARNING
python -m src.cli.commands export --format json --output syslog_dump.json --program kernel
```

## Docker

Build and run with Docker Compose:

```bash
docker-compose -f docker/docker-compose.yml up --build
```

The dashboard is exposed on port `8000`.

## Render Deployment

The repository includes:

- `render.yaml` for Render service configuration
- `scripts/render_start.sh` to start demo log generation, the ingestion daemon, and the FastAPI web server
- `.github/workflows/deploy_render.yml` to trigger Render deploys from GitHub Actions

Required GitHub Actions secrets:

```text
RENDER_API_KEY
RENDER_SERVICE_ID_WEB
```

Recommended Render environment variables:

```text
DB_PATH=data/logguard.db
LOGS_DIR=logs
DEMO_LOGS=true
```

Render start command:

```bash
bash ./scripts/render_start.sh
```

Set `DEMO_LOGS=false` for a production-style deployment that only ingests real mounted/written log files.

## Health Endpoints

```text
/healthz
/readyz
```

## Security Notes

- Do not commit real logs, `.env` files, local databases, or service credentials.
- Store deployment credentials in GitHub Secrets or the Render dashboard.
- Rotate exposed API keys immediately if they are ever pasted into chat, logs, or commits.
- The hosted demo intentionally generates simulated security alerts; they are not attacks against the live service.

## Status

LogGuard is deployed and operational. The live dashboard is available at:

```text
https://logguard-l31x.onrender.com
```
