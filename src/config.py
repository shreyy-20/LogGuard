import os
import yaml
from typing import Dict, Any, List

class LogSourceConfig:
    def __init__(self, data: Dict[str, Any]):
        self.path = data.get("path", "")
        self.type = data.get("type", "syslog")
        self.name = data.get("name", "Unnamed Log")
        self.custom_regex = data.get("custom_regex")
        self.custom_timestamp_format = data.get("custom_timestamp_format")

class DatabaseConfig:
    def __init__(self, data: Dict[str, Any]):
        self.db_path = os.getenv("DB_PATH", data.get("db_path", "logguard.db"))
        self.batch_size = int(data.get("batch_size", 100))
        self.flush_interval_seconds = float(data.get("flush_interval_seconds", 1.0))

class RuleConfig:
    def __init__(self, data: Dict[str, Any]):
        self.brute_force_enabled = data.get("brute_force", {}).get("enabled", True)
        self.brute_force_threshold = int(data.get("brute_force", {}).get("threshold_attempts", 5))
        self.brute_force_window = int(data.get("brute_force", {}).get("window_seconds", 60))
        self.brute_force_severity = data.get("brute_force", {}).get("alert_severity", "CRITICAL")

        self.repeated_failures_enabled = data.get("repeated_failures", {}).get("enabled", True)
        self.repeated_failures_threshold = int(data.get("repeated_failures", {}).get("threshold_repeats", 10))
        self.repeated_failures_window = int(data.get("repeated_failures", {}).get("window_seconds", 30))
        self.repeated_failures_severity = data.get("repeated_failures", {}).get("alert_severity", "WARNING")

        self.critical_keywords = data.get("critical_keywords", [])

class NotificationConfig:
    def __init__(self, data: Dict[str, Any]):
        self.desktop_enabled = data.get("desktop", {}).get("enabled", True)
        self.desktop_timeout = int(data.get("desktop", {}).get("timeout_seconds", 5))

        email_data = data.get("email", {})
        self.email_enabled = email_data.get("enabled", False)
        self.smtp_host = email_data.get("smtp_host", "")
        self.smtp_port = int(email_data.get("smtp_port", 587))
        self.smtp_username = email_data.get("smtp_username", "")
        self.smtp_password = email_data.get("smtp_password", "")
        self.from_email = email_data.get("from_email", "")
        self.to_email = email_data.get("to_email", "")

class AppConfig:
    def __init__(self, data: Dict[str, Any]):
        self.database = DatabaseConfig(data.get("database", {}))
        self.sources = [LogSourceConfig(s) for s in data.get("sources", [])]
        logs_dir = os.getenv("LOGS_DIR")
        if logs_dir:
            for source in self.sources:
                source.path = os.path.join(logs_dir, os.path.basename(source.path))
        self.rules = RuleConfig(data.get("rules", {}))
        self.notifications = NotificationConfig(data.get("notifications", {}))

def load_config(config_path: str = "config/config.yaml") -> AppConfig:
    """Loads configuration from a YAML file."""
    if not os.path.exists(config_path):
        # Try parent directory relative path or look up config directory
        possible_paths = [
            config_path,
            os.path.join(os.path.dirname(__file__), "..", config_path),
            os.path.join(os.getcwd(), config_path)
        ]
        for path in possible_paths:
            if os.path.exists(path):
                config_path = path
                break
        else:
            raise FileNotFoundError(f"Configuration file not found at any searched path. Current dir: {os.getcwd()}")

    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    return AppConfig(data)
