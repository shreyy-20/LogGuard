import re
import time
import threading
import logging
from collections import defaultdict
from typing import Dict, Any, List, Optional, Callable
from src.config import AppConfig

logger = logging.getLogger("LogGuard.Analyzer")

class LogAnalyzer:
    """Analyzes logs in real-time, detecting signatures, brute force attempts, and rate anomalies."""
    def __init__(self, config: AppConfig, alert_callback: Callable[[Dict[str, Any]], None]):
        self.config = config
        self.alert_callback = alert_callback
        self.lock = threading.Lock()

        # Brute force tracking: ip -> list of timestamps (floats)
        self.failed_auth_tracks = defaultdict(list)
        # Track usernames targeted to report details: ip -> username
        self.auth_ip_user = {}

        # Repeated failures tracking: message_hash -> list of timestamps
        self.message_repeats = defaultdict(list)

        # Anomaly detection: program -> list of log arrival timestamps in the last 60s
        self.program_rates = defaultdict(list)
        # Store moving average rate (logs per second) and window count
        self.program_historical_avg = {}
        self.program_historical_std = {}

        # Precompile config keywords patterns
        self.compiled_rules = []
        for rule in self.config.rules.critical_keywords:
            try:
                self.compiled_rules.append({
                    "pattern": re.compile(rule["pattern"]),
                    "severity": rule.get("severity", "WARNING"),
                    "category": rule.get("category", "General"),
                    "message_template": rule.get("message", "Rule matched")
                })
            except Exception as e:
                logger.error(f"Error compiling regex pattern '{rule.get('pattern')}': {e}")

    def analyze(self, log_entry: Dict[str, Any]):
        """Analyzes a single log entry and triggers alerts if rules are violated."""
        with self.lock:
            # 1. Signature Keyword Matching
            self._check_signatures(log_entry)

            # 2. Authentication Brute Force Detection
            self._check_brute_force(log_entry)

            # 3. Repeated Failure Detection
            self._check_repeated_failures(log_entry)

            # 4. Statistical Rate Anomaly Detection
            self._check_rate_anomalies(log_entry)

    def _trigger_alert(self, alert_type: str, severity: str, message: str, log_entry: Dict[str, Any]):
        """Helper to package and dispatch alerts."""
        alert = {
            "timestamp": log_entry["timestamp"],
            "alert_type": alert_type,
            "severity": severity,
            "message": f"[{log_entry['program']}] {message}",
            "resolved": 0
        }
        logger.warning(f"ALERT [{severity}] - {alert_type}: {message}")
        self.alert_callback(alert)

    def _check_signatures(self, log_entry: Dict[str, Any]):
        """Checks the log message against precompiled warning/critical signatures."""
        message = log_entry["message"]
        for rule in self.compiled_rules:
            if rule["pattern"].search(message):
                alert_msg = f"{rule['category']}: {rule['message_template']} (Found: '{message}')"
                self._trigger_alert(
                    alert_type=rule["category"].upper().replace(" ", "_"),
                    severity=rule["severity"],
                    message=alert_msg,
                    log_entry=log_entry
                )

    def _check_brute_force(self, log_entry: Dict[str, Any]):
        """Tracks authentication failures by source IP within a sliding window."""
        if not self.config.rules.brute_force_enabled:
            return

        metadata = log_entry.get("metadata", {})
        auth_event = metadata.get("auth_event")
        
        # We only care about failed/invalid logins
        if auth_event not in ["FAILED", "INVALID_USER"]:
            return

        ip = metadata.get("ip")
        user = metadata.get("user", "unknown")
        if not ip:
            return

        now = time.time()
        self.failed_auth_tracks[ip].append(now)
        self.auth_ip_user[ip] = user

        # Prune logs outside sliding window
        window = self.config.rules.brute_force_window
        self.failed_auth_tracks[ip] = [t for t in self.failed_auth_tracks[ip] if now - t <= window]

        # Check threshold
        failures_count = len(self.failed_auth_tracks[ip])
        if failures_count >= self.config.rules.brute_force_threshold:
            alert_msg = f"Brute force SSH attempt from IP {ip} targeting user '{user}' ({failures_count} failures in last {window} seconds)"
            # Clear tracks to avoid spamming alerts on every subsequent failure
            self.failed_auth_tracks[ip] = []
            
            self._trigger_alert(
                alert_type="AUTH_BRUTE_FORCE",
                severity=self.config.rules.brute_force_severity,
                message=alert_msg,
                log_entry=log_entry
            )

    def _check_repeated_failures(self, log_entry: Dict[str, Any]):
        """Detects if the exact same message is repeating in a short period."""
        if not self.config.rules.repeated_failures_enabled:
            return

        # Only check repeating warnings or errors to reduce overhead
        if log_entry["log_level"] not in ["WARNING", "ERROR", "CRITICAL"]:
            return

        # Use combination of program + message structure as key
        # Remove variable numbers/hex to generalize messages
        clean_msg = re.sub(r"\d+", "N", log_entry["message"])
        clean_msg = re.sub(r"0x[0-9a-fA-F]+", "HEX", clean_msg)
        msg_key = f"{log_entry['program']}:{clean_msg}"

        now = time.time()
        self.message_repeats[msg_key].append(now)

        # Prune
        window = self.config.rules.repeated_failures_window
        self.message_repeats[msg_key] = [t for t in self.message_repeats[msg_key] if now - t <= window]

        repeats_count = len(self.message_repeats[msg_key])
        if repeats_count >= self.config.rules.repeated_failures_threshold:
            alert_msg = f"Repeated Failure Pattern: Message '{log_entry['message'][:60]}...' repeated {repeats_count} times in last {window} seconds"
            self.message_repeats[msg_key] = []  # Reset
            
            self._trigger_alert(
                alert_type="REPEATED_FAILURES",
                severity=self.config.rules.repeated_failures_severity,
                message=alert_msg,
                log_entry=log_entry
            )

    def _check_rate_anomalies(self, log_entry: Dict[str, Any]):
        """Detects sudden volume surges for a given program using simple statistical thresholds."""
        prog = log_entry["program"]
        now = time.time()

        # Add current event timestamp
        self.program_rates[prog].append(now)

        # Slide window (60 seconds)
        self.program_rates[prog] = [t for t in self.program_rates[prog] if now - t <= 60]
        current_rate = len(self.program_rates[prog])

        # We need historical samples before drawing conclusions (let's say 20 logs)
        # Update historical statistics in a simplified online format
        if prog not in self.program_historical_avg:
            self.program_historical_avg[prog] = float(current_rate)
            self.program_historical_std[prog] = 1.0  # seed standard deviation
            return

        avg = self.program_historical_avg[prog]
        std = self.program_historical_std[prog]

        # Trigger anomaly if current 60s rate is 3 standard deviations above average
        # Ensure we have at least 15 logs as a baseline to prevent alerts on quiet components spiking from 1 to 3 logs
        if current_rate > 15 and current_rate > (avg + 3 * std):
            alert_msg = f"Traffic Anomaly: Program '{prog}' experienced sudden log volume spike ({current_rate} logs/min, normal average: {avg:.1f}/min)"
            # Set avg to current_rate to prevent spamming while rate remains high
            self.program_historical_avg[prog] = float(current_rate)
            
            self._trigger_alert(
                alert_type="VOLUME_ANOMALY",
                severity="WARNING",
                message=alert_msg,
                log_entry=log_entry
            )
        else:
            # Welford's algorithm or simple running average update
            # We decay history slowly to adapt to new baselines
            alpha = 0.05  # Weight of new sample
            self.program_historical_avg[prog] = (1 - alpha) * avg + alpha * current_rate
            diff = abs(current_rate - avg)
            self.program_historical_std[prog] = (1 - alpha) * std + alpha * max(diff, 1.0)
