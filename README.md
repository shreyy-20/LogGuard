# 🛡️ LogGuard - Linux Log Monitoring & Analysis Tool

**LogGuard** is a high-performance, production-ready, edge-first log monitoring and security analysis tool. Built from scratch using Python, optimized SQLite schemas, and Linux system logging paradigms, it offers real-time file monitoring, security signature analysis, SSH brute force protection, standard SQL querying, an interactive Terminal user interface (TUI), and a modern Web Analytics dashboard.

---

## 🚀 Key Features

*   **Real-Time Multi-Threaded Tailing**: Concurrently monitors multiple log files (`syslog`, `auth.log`, `kern.log`, custom apps) using cross-platform file descriptor trackers that gracefully handle file rotation and in-place truncations.
*   **Security & Threat Auditing**: Detects SSH/auth brute force attacks, repeated application crashes, and resource-exhaustion events (OOM Killer) in real-time.
*   **Zero-Dependency Local Storage**: Uses a local SQLite database configured with Write-Ahead Logging (WAL) and synchronous transaction batching to handle high-frequency writes without database locking.
*   **Blazing-Fast Keyword Searches**: Features a built-in SQLite FTS5 (Full-Text Search) engine for instantaneous keyword lookups, avoiding slow linear reads.
*   **Interactive TUI Dashboard**: An interactive split-screen terminal control room built on Python's `rich` library showing real-time statistics, warning rates, alert feeds, and log streams.
*   **FastAPI Glassmorphism Web Console**: A dark-themed, glassmorphic single-page web console featuring interactive data visualizations (Chart.js), API query interfaces, and alert resolution tools.
*   **SMTP & System Alerting**: Dispatches background email notifications and system desktop alert bubbles immediately when warning or critical threat thresholds are breached.

---

## 🛠️ Installation & Quick Start

### 1. Local Setup (Python)

Ensure Python 3.9+ is installed on your system.

```bash
# Clone or copy the project into a folder
cd Linux/

# Install python dependencies
pip install -r requirements.txt
```

### 2. Running the Simulated Log Generator (Demo Mode)

Since Linux logs are highly active, we package a **mock log simulator**. This streams simulated system logs, SSH attacks, and kernel crashes into a local `logs/` directory—perfect for evaluating LogGuard on Windows or inside local dev sandboxes.

```bash
# Run the mock log generator in a terminal window
python scripts/generate_mock_logs.py
```

### 3. Launching LogGuard Core Daemon

The background daemon handles real-time log tailing, parsing, DB indexing, and threat detection.

```bash
# Start the monitoring engine
python -m src.main
```

### 4. Running the Interactive CLI Dashboard (TUI)

With the daemon running (or logs already ingested), launch the interactive terminal panel:

```bash
python src/main.py --dashboard
# or using the CLI command:
python -m src.cli.commands dashboard
```

### 5. Running the Web Console

Start the FastAPI web server to inspect the dashboard in your web browser:

```bash
# Start the server
python src/web/app.py
```
Open your browser and navigate to: **[http://localhost:8000](http://localhost:8000)**

---

## 📖 CLI User Manual

LogGuard exposes a standard, easy-to-use Command Line Interface (`click`-based) to query, inspect, and export your logs:

### 1. Search and Filter Logs
Query log entries with SQL-backed filters:
```bash
# Search logs by severity level
python -m src.cli.commands search --level CRITICAL

# Filter by program and limit results
python -m src.cli.commands search --program sshd --limit 10

# Search logs using indexed FTS5 keyword query (instantaneous)
python -m src.cli.commands search --keyword "failed password"

# Filter by time range
python -m src.cli.commands search --since "2026-05-24 01:00:00" --until "2026-05-24 02:00:00"
```

### 2. View System Metrics & Statistics
Retrieve parsed log counts, severity distribution, and top log contributors:
```bash
python -m src.cli.commands stats
```

### 3. Review Security Warnings
Retrieve triggered alerts list:
```bash
# Show all alerts
python -m src.cli.commands alerts

# Show unresolved alerts only
python -m src.cli.commands alerts --unresolved
```

### 4. Export Logs
Export query results to structured `CSV` or `JSON` formats for offline analysis:
```bash
# Export to CSV
python -m src.cli.commands export --format csv --output security_report.csv --level WARNING

# Export to JSON
python -m src.cli.commands export --format json --output syslog_dump.json --program kernel
```

---

## 🐳 Docker Deployment

To deploy LogGuard containerized on a server or Kubernetes cluster:

### Build and Run with Docker Compose
We decouple the background monitor from the web panel into separate containers using a shared volume:

```bash
# Start the daemon and web console container stack
docker-compose -f docker/docker-compose.yml up --build -d

# Verify containers are running
docker ps
```
*   The **web dashboard** will be exposed on **port 8000**.
*   The SQLite database is persisted in `./data/logguard.db` in the host.
*   To monitor host system logs, map `/var/log` on the host to `/app/logs` inside the `docker-compose.yml` volumes section.

---

## ⚙️ Service Setup on Production Linux Servers

To run LogGuard persistently as a background system service on production Linux servers (Systemd):

```bash
# Run the setup script as root (sudo)
sudo bash scripts/setup.sh

# Start the system service
sudo systemctl start logguard

# Enable the service to launch at boot
sudo systemctl enable logguard

# Check service status
sudo systemctl status logguard
```
Once installed via the script, the global alias `logguard` is created. You can run CLI commands from anywhere on the system:
```bash
logguard stats
logguard search --level ERROR --limit 5
```

---

## 📁 Project Directory Map

```
Linux/
├── .github/
│   └── workflows/
│       └── ci.yml             # GitHub Actions CI pipeline
├── config/
│   └── config.yaml            # Main configuration (Sources, Rules, Alerts)
├── docker/
│   ├── Dockerfile             # Multi-stage image build
│   └── docker-compose.yml     # Multi-container orchestration stack
├── scripts/
│   ├── generate_mock_logs.py  # Mock log stream generator
│   └── setup.sh               # Systemd installer for Linux
├── src/
│   ├── __init__.py
│   ├── main.py                # Main daemon orchestrator
│   ├── config.py              # YAML config loader
│   ├── parser.py              # Normalization parsers
│   ├── database.py            # SQLite WAL batch writer
│   ├── monitor.py             # Multi-threaded tailer
│   ├── analyzer.py            # Threat & anomaly detection
│   ├── alerter.py             # SMTP & desktop alerts
│   ├── cli/
│   │   ├── __init__.py
│   │   ├── commands.py        # Click CLI subcommands
│   │   └── dashboard.py       # Rich Live TUI panel
│   └── web/
│       ├── __init__.py
│       ├── app.py             # FastAPI Web Application
│       ├── templates/
│       │   └── index.html     # Glassmorphism HTML page
│       └── static/
│           └── style.css      # Dark-theme stylesheet
├── tests/
│   ├── test_parser.py
│   ├── test_database.py
│   ├── test_analyzer.py
│   └── test_monitor.py
├── requirements.txt           # PIP dependencies
├── pyproject.toml             # PyTest and package configuration
└── ARCHITECTURE.md            # Deep-dive architecture design guide
```

---

**Preparing This Repository For Public Publishing (Recommended)**

- **Never commit secrets or real logs.** Keep `config/config.yaml` out of commits and use `config/config.sample.env` or a secrets manager instead.
- **Install local pre-commit checks** to catch secrets before pushes:
	- `pip install pre-commit`
	- `pre-commit install --hook-type pre-push`
	- `pre-commit run --all-files` to run checks manually.
- **Scrub history if sensitive data was already committed.** Use `git-filter-repo` or BFG to remove files or secrets from history (this rewrites history and requires a force-push):

	Example (BFG):
	- `bfg --delete-folders logs/ --no-blob-protection`
	- `git reflog expire --expire=now --all && git gc --prune=now --aggressive`
	- `git push --force --all`

	Example (git-filter-repo):
	- `git filter-repo --invert-paths --path logs/`

- **Rotate any exposed secrets** after history rewrite and inform collaborators.

**Publishing Checklist**

- Add `.gitignore` to cover `logs/`, `data/`, `*.db`, `.env`, `config/config.yaml`, and `.venv/`.
- Provide `config/config.sample.env` as a template — fill values through CI or secrets manager on deployment.
- Run `pre-commit` and the secret scanners locally before pushing.
- Add a CI secret scanning step (we include a GitHub Actions job in `.github/workflows/ci.yml`).

If you want, I can also:

- Add a `.pre-commit-config.yaml` (I added one with `detect-secrets` and `gitleaks`).
- Provide exact `bfg` or `git-filter-repo` commands tailored to the repo state.
- Prepare provider-specific deployment config (Render/Fly/DigitalOcean/AWS/Azure) — tell me which provider you prefer and I will add step-by-step config and a sample GitHub Actions deploy workflow.

**Render Deployment (added)**

- A `render.yaml` manifest has been added to define two services: `LogGuard Web` and `LogGuard Daemon`. You can import this file into Render's dashboard when creating a new service or use it as a starting point.
- A GitHub Actions workflow `.github/workflows/deploy_render.yml` has been added. On pushes to `main` it triggers a deploy for each Render service via the Render API.

To complete deployment on Render:

1. Create two services in the Render dashboard (or import `render.yaml`) named `LogGuard Web` and `LogGuard Daemon`.
2. Configure the web service `Start Command` to: `uvicorn src.web.app:app --host 0.0.0.0 --port 8000`.
3. Configure the daemon service `Start Command` to: `python -m src.main`.
4. Add persistent disk or DB path for `DB_PATH` in the Render environment variables (e.g. `/var/lib/logguard/logguard.db`).
5. In your repository settings, add the following GitHub Secrets:
	- `RENDER_API_KEY` — Create a Render API key from your Render dashboard (account → API keys).
	- `RENDER_SERVICE_ID_WEB` — Service ID for the web service (found on the service settings page).
	- `RENDER_SERVICE_ID_DAEMON` — Service ID for the daemon/worker service.
6. Push to `main` — the workflow will call the Render API to create a deploy for each service.

Additional notes:

- For production, run Uvicorn with multiple workers to utilize multiple CPU cores. Example `Start Command`:

	`uvicorn src.web.app:app --host 0.0.0.0 --port 8000 --workers 4`

- The web app exposes health endpoints used by Render or load balancers:
	- `/healthz` — liveness probe (returns 200). 
	- `/readyz` — readiness probe (performs a light DB query; returns 200 when ready).

- To fetch your Render service IDs programmatically, use the helper script:

```bash
export RENDER_API_KEY="<your-key>"
python scripts/get_render_service_ids.py
```


Notes:
- Render will build the Docker image using your repository's `Dockerfile` (multi-service projects get separate service builds).
- Keep secrets out of `config/config.yaml`; prefer environment variables set in Render.


