import os
import sys
import uvicorn
from fastapi import FastAPI, Request, Query, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from src.config import load_config
from src.database import DatabaseManager

app = FastAPI(title="LogGuard Web Console", description="A premium dashboard for log analysis.")

# Resolve absolute paths for static files and templates
base_dir = os.path.dirname(os.path.abspath(__file__))
static_dir = os.path.join(base_dir, "static")
templates_dir = os.path.join(base_dir, "templates")

# Ensure directories exist
os.makedirs(static_dir, exist_ok=True)
os.makedirs(templates_dir, exist_ok=True)

# Mount static and templates engines
app.mount("/static", StaticFiles(directory=static_dir), name="static")
templates = Jinja2Templates(directory=templates_dir)

# Initialize DB Manager
config = load_config("config/config.yaml")
db = DatabaseManager(
    db_path=config.database.db_path,
    batch_size=config.database.batch_size,
    flush_interval=config.database.flush_interval_seconds
)
db.stop() # Running web server only reads from DB, no daemon queue needed


@app.get("/healthz")
def health_check():
    """Liveness probe for container orchestration and load balancers."""
    return {"status": "ok"}


@app.get("/readyz")
def readiness_check():
    """Readiness probe: verify DB is accessible and basic query works."""
    try:
        # perform a light-weight DB operation
        _ = db.query_logs(limit=1)
        return {"status": "ready"}
    except Exception as e:
        raise HTTPException(status_code=503, detail="db-unavailable")

@app.get("/", response_class=HTMLResponse)
def read_root(request: Request):
    """Renders the main glassmorphism HTML dashboard."""
    return templates.TemplateResponse("index.html", {"request": request, "app_title": "LogGuard"})

@app.get("/api/stats")
def get_dashboard_stats():
    """Endpoint returning system log metrics, level distribution, and charts data."""
    try:
        return db.get_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/logs")
def get_logs(
    since: str = Query(None, description="Start timestamp YYYY-MM-DD HH:MM:SS"),
    until: str = Query(None, description="End timestamp YYYY-MM-DD HH:MM:SS"),
    level: str = Query(None, description="Log level"),
    source: str = Query(None, description="Source name"),
    program: str = Query(None, description="Program name"),
    keyword: str = Query(None, description="FTS keyword match"),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    """Endpoint returning paginated log search results."""
    try:
        return db.query_logs(
            since=since,
            until=until,
            log_level=level,
            source_file=source,
            program=program,
            keyword=keyword,
            limit=limit,
            offset=offset
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/alerts")
def get_alerts(
    limit: int = Query(50, ge=1),
    unresolved_only: bool = Query(False)
):
    """Endpoint returning security alerts list."""
    try:
        return db.get_alerts(limit=limit, unresolved_only=unresolved_only)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: int):
    """Endpoint to mark a security alert as resolved."""
    try:
        db.resolve_alert(alert_id)
        return {"status": "success", "message": f"Alert {alert_id} resolved"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def run_server():
    """Starts the FastAPI Web Server using Uvicorn."""
    print("----------------------------------------------------------------")
    print("Starting LogGuard Web Console at: http://localhost:8000")
    print("----------------------------------------------------------------")
    uvicorn.run(app, host="0.0.0.0", port=8000)

if __name__ == "__main__":
    run_server()
