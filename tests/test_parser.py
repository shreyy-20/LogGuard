import unittest
from datetime import datetime
from src.parser import LogParser

class TestLogParser(unittest.TestCase):
    def test_parse_rfc3164_syslog(self):
        """Tests parsing traditional syslog format (RFC 3164)."""
        line = "May 24 01:40:15 myhost myprocess[1234]: Hello world message"
        parsed = LogParser.parse_syslog(line)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["program"], "myprocess")
        self.assertEqual(parsed["pid"], 1234)
        self.assertEqual(parsed["message"], "Hello world message")
        self.assertEqual(parsed["log_level"], "INFO")
        self.assertTrue(parsed["timestamp"].endswith("01:40:15"))

    def test_parse_rfc5424_syslog(self):
        """Tests parsing modern syslog format (RFC 5424)."""
        line = "2026-05-24T01:40:15.123Z host-1 nginx[500]: 127.0.0.1 - GET /index.html"
        parsed = LogParser.parse_syslog(line)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["program"], "nginx")
        self.assertEqual(parsed["pid"], 500)
        self.assertEqual(parsed["message"], "127.0.0.1 - GET /index.html")
        self.assertEqual(parsed["timestamp"], "2026-05-24 01:40:15")

    def test_parse_auth_failure(self):
        """Tests parsing sshd login failures and extracting metadata (IP and user)."""
        line = "May 24 01:40:15 myhost sshd[9876]: Failed password for admin from 198.51.100.42 port 54321 ssh2"
        parsed = LogParser.parse_auth(line)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["log_level"], "WARNING")
        self.assertIn("metadata", parsed)
        self.assertEqual(parsed["metadata"]["auth_event"], "FAILED")
        self.assertEqual(parsed["metadata"]["user"], "admin")
        self.assertEqual(parsed["metadata"]["ip"], "198.51.100.42")

    def test_parse_auth_success(self):
        """Tests parsing successful sshd logins."""
        line = "May 24 01:40:15 myhost sshd[9876]: Accepted password for root from 192.168.1.15 port 22 ssh2"
        parsed = LogParser.parse_auth(line)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["log_level"], "INFO")
        self.assertEqual(parsed["metadata"]["auth_event"], "SUCCESS")
        self.assertEqual(parsed["metadata"]["user"], "root")
        self.assertEqual(parsed["metadata"]["ip"], "192.168.1.15")

    def test_parse_kern_oom(self):
        """Tests parsing critical kernel logs like out-of-memory triggers."""
        line = "May 24 01:40:15 myhost kernel: Out of memory: Kill process 123 (java) score 999"
        parsed = LogParser.parse_kern(line)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["log_level"], "CRITICAL")
        self.assertEqual(parsed["program"], "kernel")

    def test_parse_custom_log(self):
        """Tests parsing custom log formats using custom regex patterns."""
        line = "[2026-05-24 01:40:15] [ERROR] [Controller] Database connection failed"
        regex = r"^\[(?P<timestamp>[^\]]+)\]\s+\[(?P<level>[^\]]+)\]\s+\[(?P<source>[^\]]+)\]\s+(?P<message>.*)$"
        ts_format = "%Y-%m-%d %H:%M:%S"
        
        parsed = LogParser.parse_custom(line, regex, ts_format)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["timestamp"], "2026-05-24 01:40:15")
        self.assertEqual(parsed["log_level"], "ERROR")
        self.assertEqual(parsed["program"], "Controller")
        self.assertEqual(parsed["message"], "Database connection failed")

if __name__ == "__main__":
    unittest.main()
