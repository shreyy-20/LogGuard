import os
import sys
import time
import signal
import logging
from src.config import load_config, AppConfig
from src.parser import LogParser
from src.database import DatabaseManager
from src.analyzer import LogAnalyzer
from src.alerter import AlertDispatcher
from src.monitor import LogMonitor

# Configure standard console logging for LogGuard daemon
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("logguard_daemon.log", encoding="utf-8")
    ]
)
logger = logging.getLogger("LogGuard.Main")

class LogGuardDaemon:
    """The central daemon coordinating tailing, parsing, db saving, and alerting."""
    def __init__(self, config_path: str = "config/config.yaml"):
        self.config: AppConfig = load_config(config_path)
        self.db = DatabaseManager(
            db_path=self.config.database.db_path,
            batch_size=self.config.database.batch_size,
            flush_interval=self.config.database.flush_interval_seconds
        )
        self.alerter = AlertDispatcher(self.config.notifications)
        self.analyzer = LogAnalyzer(self.config, self._on_alert_triggered)
        self.monitor = None
        self.running = False

        # Build mapping of file path -> source configuration
        self.source_map = {os.path.abspath(s.path): s for s in self.config.sources}
        logger.info(f"Loaded config. Tracking {len(self.source_map)} sources.")

    def _on_alert_triggered(self, alert_entry: dict):
        """Called when analyzer triggers a security/system alert."""
        # Save alert async to DB
        self.db.insert_alert_async(alert_entry)
        # Send via email/desktop alert
        self.alerter.dispatch(alert_entry)

    def _on_log_line_tailed(self, line: str, file_path: str):
        """Called when a tailer thread reads a raw line from a file."""
        abs_path = os.path.abspath(file_path)
        source_conf = self.source_map.get(abs_path)
        if not source_conf:
            return

        parsed = None
        try:
            # Route line parsing based on source configuration type
            if source_conf.type == "syslog":
                parsed = LogParser.parse_syslog(line)
            elif source_conf.type == "auth":
                parsed = LogParser.parse_auth(line)
            elif source_conf.type == "kern":
                parsed = LogParser.parse_kern(line)
            elif source_conf.type == "custom":
                parsed = LogParser.parse_custom(
                    line, 
                    source_conf.custom_regex, 
                    source_conf.custom_timestamp_format
                )
        except Exception as e:
            logger.debug(f"Parser exception for line in {source_conf.name}: {e}")

        # If parsed successfully, enrich, save, and analyze
        if parsed:
            parsed["source_file"] = source_conf.name
            
            # 1. Store async in SQLite
            self.db.insert_log_async(parsed)
            
            # 2. Feed into real-time analyzer for rule matching
            self.analyzer.analyze(parsed)

    def start(self):
        """Starts the monitoring daemon processes."""
        self.running = True
        paths = [s.path for s in self.config.sources]
        
        # Start LogMonitor
        self.monitor = LogMonitor(paths, self._on_log_line_tailed)
        self.monitor.start()
        logger.info("LogGuard daemon engine fully online. Monitoring started.")

    def stop(self):
        """Clean shutdown of database and monitors."""
        if not self.running:
            return
        self.running = False
        logger.info("Shutting down LogGuard daemon...")
        
        if self.monitor:
            self.monitor.stop()
            
        if self.db:
            self.db.stop()
            
        logger.info("LogGuard shut down cleanly.")

def run_daemon():
    daemon = LogGuardDaemon()
    daemon.start()

    # Register OS signal handlers for graceful exit
    def signal_handler(sig, frame):
        logger.info("Exit signal received.")
        daemon.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    logger.info("Press Ctrl+C to stop.")
    while True:
        time.sleep(1)

if __name__ == "__main__":
    run_daemon()
