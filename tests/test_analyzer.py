import unittest
import time
from src.config import AppConfig
from src.analyzer import LogAnalyzer

class MockConfig:
    """Mock application configuration for analysis testing."""
    class DatabaseMock:
        db_path = ":memory:"
        batch_size = 1
        flush_interval_seconds = 0.1

    class RulesMock:
        brute_force_enabled = True
        brute_force_threshold = 3  # Low threshold for unit tests
        brute_force_window = 10
        brute_force_severity = "CRITICAL"

        repeated_failures_enabled = True
        repeated_failures_threshold = 4  # Low threshold for unit tests
        repeated_failures_window = 10
        repeated_failures_severity = "WARNING"

        critical_keywords = [
            {"pattern": "Out of memory", "severity": "CRITICAL", "category": "Resource Exhaustion", "message": "OOM killer"},
            {"pattern": "segfault", "severity": "CRITICAL", "category": "Application Crash", "message": "Segfault error"}
        ]

    class NotificationsMock:
        desktop_enabled = False
        desktop_timeout = 1
        email_enabled = False

    def __init__(self):
        self.database = self.DatabaseMock()
        self.rules = self.RulesMock()
        self.notifications = self.NotificationsMock()

class TestLogAnalyzer(unittest.TestCase):
    def setUp(self):
        self.triggered_alerts = []
        # Callback to collect triggered alerts
        def alert_callback(alert):
            self.triggered_alerts.append(alert)

        self.config = MockConfig()
        # Cast to AppConfig type for analyzer
        self.analyzer = LogAnalyzer(self.config, alert_callback)

    def test_signature_matching(self):
        """Verifies critical keywords trigger alerts immediately."""
        log = {
            "timestamp": "2026-05-24 01:40:15",
            "log_level": "ERROR",
            "program": "kernel",
            "message": "Out of memory: Kill process 123",
            "raw_line": "Out of memory: Kill process 123"
        }

        self.analyzer.analyze(log)
        self.assertEqual(len(self.triggered_alerts), 1)
        self.assertEqual(self.triggered_alerts[0]["alert_type"], "RESOURCE_EXHAUSTION")
        self.assertEqual(self.triggered_alerts[0]["severity"], "CRITICAL")

    def test_ssh_brute_force_detection(self):
        """Verifies failed auth attempts exceeding threshold triggers brute-force alert."""
        # 3 failed attempts (matching our mock config threshold=3)
        ip = "192.0.2.1"
        for i in range(3):
            log = {
                "timestamp": f"2026-05-24 01:40:{10+i}",
                "log_level": "WARNING",
                "program": "sshd",
                "message": f"Failed password for admin from {ip} port 12345 ssh2",
                "metadata": {
                    "auth_event": "FAILED",
                    "user": "admin",
                    "ip": ip
                }
            }
            self.analyzer.analyze(log)

        # Triggered count should be exactly 1 brute force alert
        self.assertEqual(len(self.triggered_alerts), 1)
        self.assertEqual(self.triggered_alerts[0]["alert_type"], "AUTH_BRUTE_FORCE")
        self.assertEqual(self.triggered_alerts[0]["severity"], "CRITICAL")
        self.assertIn("192.0.2.1", self.triggered_alerts[0]["message"])

    def test_repeated_failures_detection(self):
        """Verifies repeating warning messages trigger repeated failure alert."""
        # Trigger same error 4 times (mock config threshold=4)
        for i in range(4):
            log = {
                "timestamp": f"2026-05-24 01:40:{10+i}",
                "log_level": "WARNING",
                "program": "nginx",
                "message": "upstream connection refused while connecting to upstream",
                "raw_line": "nginx upstream connection refused"
            }
            self.analyzer.analyze(log)

        # Triggered repeated failure alert
        self.assertEqual(len(self.triggered_alerts), 1)
        self.assertEqual(self.triggered_alerts[0]["alert_type"], "REPEATED_FAILURES")
        self.assertEqual(self.triggered_alerts[0]["severity"], "WARNING")

if __name__ == "__main__":
    unittest.main()
