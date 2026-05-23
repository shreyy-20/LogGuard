import os
import time
import unittest
from src.database import DatabaseManager

class TestDatabaseManager(unittest.TestCase):
    def setUp(self):
        self.db_path = f"test_logguard_{self._testMethodName}.db"
        # Setup DB with small flush interval for fast testing
        self.db = DatabaseManager(self.db_path, batch_size=10, flush_interval=0.1)

    def tearDown(self):
        # Shut down DB writer before deleting file
        self.db.stop()
        # Clean up database files
        for suffix in ["", "-wal", "-shm"]:
            f_path = f"{self.db_path}{suffix}"
            if os.path.exists(f_path):
                try:
                    os.remove(f_path)
                except Exception:
                    pass

    def test_log_insertion_and_query(self):
        """Verifies asynchronous insertion and filtering capabilities."""
        log_entry = {
            "timestamp": "2026-05-24 01:40:15",
            "log_level": "ERROR",
            "source_file": "System Log",
            "program": "sshd",
            "pid": 1234,
            "message": "Failed connection attempt",
            "raw_line": "May 24 01:40:15 srv sshd[1234]: Failed connection attempt"
        }

        self.db.insert_log_async(log_entry)
        
        # Manually trigger flush to speed up testing without waiting for timer
        self.db._flush_queue()

        logs = self.db.query_logs(log_level="ERROR")
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["program"], "sshd")
        self.assertEqual(logs[0]["message"], "Failed connection attempt")

    def test_fts5_keyword_search(self):
        """Validates SQLite FTS5 search capabilities."""
        logs = [
            {
                "timestamp": "2026-05-24 01:40:15",
                "log_level": "INFO",
                "source_file": "System Log",
                "program": "app",
                "pid": None,
                "message": "User alice registered successfully",
                "raw_line": "User alice registered successfully"
            },
            {
                "timestamp": "2026-05-24 01:40:16",
                "log_level": "INFO",
                "source_file": "System Log",
                "program": "app",
                "pid": None,
                "message": "Payment of 50 dollars processed for user bob",
                "raw_line": "Payment of 50 dollars processed for user bob"
            }
        ]

        for log in logs:
            self.db.insert_log_async(log)
            
        self.db._flush_queue()

        # Search for "alice"
        results = self.db.query_logs(keyword="alice")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["message"], "User alice registered successfully")

        # Search for "payment" (case insensitive)
        results = self.db.query_logs(keyword="payment")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["message"], "Payment of 50 dollars processed for user bob")

    def test_alerts_insertion_and_query(self):
        """Verifies security warnings inserts and resolutions."""
        alert = {
            "timestamp": "2026-05-24 01:40:15",
            "alert_type": "AUTH_BRUTE_FORCE",
            "severity": "CRITICAL",
            "message": "SSH attack detected",
            "resolved": 0
        }

        self.db.insert_alert_async(alert)
        self.db._flush_queue()

        alerts = self.db.get_alerts(unresolved_only=True)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "AUTH_BRUTE_FORCE")

        # Resolve alert
        self.db.resolve_alert(alerts[0]["id"])
        
        active_alerts = self.db.get_alerts(unresolved_only=True)
        self.assertEqual(len(active_alerts), 0)

        all_alerts = self.db.get_alerts(unresolved_only=False)
        self.assertEqual(len(all_alerts), 1)
        self.assertEqual(all_alerts[0]["resolved"], 1)

if __name__ == "__main__":
    unittest.main()
