import re
from datetime import datetime
from typing import Dict, Any, Optional

# Month name mapping to number
MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}

# Regex for RFC 3164 (traditional syslog)
# Examples:
# May 24 01:40:15 hostname sshd[1234]: message
# May  4 01:40:15 hostname sshd: message
REGEX_RFC3164 = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+(?P<program>[a-zA-Z0-9_\-\.\/]+)(?:\[(?P<pid>\d+)\])?:?\s+(?P<message>.*)$"
)

# Regex for RFC 5424 (modern syslog)
# Example: 2026-05-24T01:40:15.123Z hostname process[123]: message
# Or: 2026-05-24T01:40:15+05:30 hostname process 123 - message
REGEX_RFC5424 = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s+"
    r"(?P<hostname>\S+)\s+(?P<program>[a-zA-Z0-9_\-\.\/]+)(?:\[(?P<pid>\d+)\])?:?\s+(?P<message>.*)$"
)

# Common regex to extract IP and user from auth messages
REGEX_AUTH_FAILED = re.compile(
    r"(?i)Failed \S+ for (?P<user>\S+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
)
REGEX_AUTH_INVALID = re.compile(
    r"(?i)Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
)
REGEX_AUTH_ACCEPTED = re.compile(
    r"(?i)Accepted \S+ for (?P<user>\S+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
)

class LogParser:
    @staticmethod
    def parse_syslog(line: str) -> Optional[Dict[str, Any]]:
        """Parses a traditional or modern syslog line."""
        line = line.strip()
        if not line:
            return None

        # 1. Try RFC 5424
        match = REGEX_RFC5424.match(line)
        if match:
            gd = match.groupdict()
            ts_str = gd["timestamp"]
            # Convert ISO 8601 to standard SQLite timestamp format (YYYY-MM-DD HH:MM:SS)
            try:
                # Truncate timezone/milliseconds for simplicity in SQLite sorting
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                timestamp = ts_str[:19].replace("T", " ")

            return {
                "timestamp": timestamp,
                "program": gd["program"],
                "pid": int(gd["pid"]) if gd["pid"] else None,
                "message": gd["message"].strip(),
                "log_level": LogParser.infer_log_level(gd["program"], gd["message"]),
                "raw_line": line
            }

        # 2. Try RFC 3164
        match = REGEX_RFC3164.match(line)
        if match:
            gd = match.groupdict()
            month_name = gd["month"]
            day = int(gd["day"])
            time_str = gd["time"]
            month = MONTH_MAP.get(month_name, 1)
            
            # Since year is missing, use current year
            current_year = datetime.now().year
            try:
                dt_str = f"{current_year}-{month:02d}-{day:02d} {time_str}"
                # Handle corner case where we are tailing last year's logs in January
                dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
                if dt > datetime.now():
                    dt_str = f"{current_year - 1}-{month:02d}-{day:02d} {time_str}"
                timestamp = dt_str
            except Exception:
                timestamp = f"{current_year}-{month:02d}-{day:02d} {time_str}"

            return {
                "timestamp": timestamp,
                "program": gd["program"],
                "pid": int(gd["pid"]) if gd["pid"] else None,
                "message": gd["message"].strip(),
                "log_level": LogParser.infer_log_level(gd["program"], gd["message"]),
                "raw_line": line
            }

        # 3. Fallback for logs that don't match standard syslog but have a timestamp at start
        # E.g. "2026-05-24 01:40:15 ..."
        try:
            ts_match = re.match(r"^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})", line)
            if ts_match:
                ts = ts_match.group(1).replace("T", " ")
                msg = line[len(ts_match.group(0)):].strip()
                # strip leading colons/spaces
                msg = re.sub(r"^:\s*", "", msg)
                return {
                    "timestamp": ts,
                    "program": "system",
                    "pid": None,
                    "message": msg,
                    "log_level": LogParser.infer_log_level("system", msg),
                    "raw_line": line
                }
        except Exception:
            pass

        # Return unparsed but structured line if nothing matches
        return {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "program": "unknown",
            "pid": None,
            "message": line,
            "log_level": LogParser.infer_log_level("unknown", line),
            "raw_line": line
        }

    @staticmethod
    def parse_auth(line: str) -> Optional[Dict[str, Any]]:
        """Parses an auth.log line and extracts authentication specific metadata."""
        parsed = LogParser.parse_syslog(line)
        if not parsed:
            return None

        # Override log level for auth failures to WARNING/CRITICAL
        msg = parsed["message"]
        parsed["metadata"] = {}

        # Check for authentication states
        failed_match = REGEX_AUTH_FAILED.search(msg)
        invalid_match = REGEX_AUTH_INVALID.search(msg)
        accepted_match = REGEX_AUTH_ACCEPTED.search(msg)

        if failed_match:
            parsed["log_level"] = "WARNING"
            parsed["metadata"] = {
                "auth_event": "FAILED",
                "user": failed_match.group("user"),
                "ip": failed_match.group("ip")
            }
        elif invalid_match:
            parsed["log_level"] = "CRITICAL"
            parsed["metadata"] = {
                "auth_event": "INVALID_USER",
                "user": invalid_match.group("user"),
                "ip": invalid_match.group("ip")
            }
        elif accepted_match:
            parsed["log_level"] = "INFO"
            parsed["metadata"] = {
                "auth_event": "SUCCESS",
                "user": accepted_match.group("user"),
                "ip": accepted_match.group("ip")
            }
        elif "authentication failure" in msg.lower():
            parsed["log_level"] = "WARNING"
            parsed["metadata"] = {"auth_event": "FAILED"}

        return parsed

    @staticmethod
    def parse_kern(line: str) -> Optional[Dict[str, Any]]:
        """Parses a kern.log line and infers correct log levels based on kernel indicators."""
        parsed = LogParser.parse_syslog(line)
        if not parsed:
            return None

        parsed["program"] = parsed.get("program") or "kernel"
        msg = parsed["message"].lower()

        # Kern logs carry highly critical hardware/kernel state logs. Adjust levels.
        if any(w in msg for w in ["panic", "fatal", "out of memory", "oom-killer", "segfault", "segmentation fault"]):
            parsed["log_level"] = "CRITICAL"
        elif any(w in msg for w in ["error", "err", "fail", "filesystem read-only", "corrupted"]):
            parsed["log_level"] = "ERROR"
        elif any(w in msg for w in ["warning", "warn", "invalid"]):
            parsed["log_level"] = "WARNING"

        return parsed

    @staticmethod
    def parse_custom(line: str, regex_pattern: str, ts_format: str) -> Optional[Dict[str, Any]]:
        """Parses a custom log format using a regex pattern."""
        line = line.strip()
        if not line:
            return None

        try:
            pattern = re.compile(regex_pattern)
            match = pattern.match(line)
            if not match:
                # Return unparsed structured log
                return {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "program": "custom",
                    "pid": None,
                    "message": line,
                    "log_level": "INFO",
                    "raw_line": line
                }

            gd = match.groupdict()
            ts_str = gd.get("timestamp", "")
            
            # Parse timestamp to target YYYY-MM-DD HH:MM:SS
            try:
                dt = datetime.strptime(ts_str, ts_format)
                timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                timestamp = ts_str

            return {
                "timestamp": timestamp,
                "program": gd.get("source") or gd.get("program") or "custom",
                "pid": int(gd.get("pid")) if gd.get("pid") and gd.get("pid").isdigit() else None,
                "message": gd.get("message", "").strip(),
                "log_level": (gd.get("level") or LogParser.infer_log_level(gd.get("source", "custom"), gd.get("message", ""))).upper(),
                "raw_line": line
            }
        except Exception:
            return {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "program": "custom-error",
                "pid": None,
                "message": line,
                "log_level": "ERROR",
                "raw_line": line
            }

    @staticmethod
    def infer_log_level(program: str, message: str) -> str:
        """Infers log levels ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL") from content cues."""
        msg = message.upper()
        prog = program.upper()

        if any(w in msg for w in ["CRITICAL", "PANIC", "FATAL", "OOM-KILLER"]):
            return "CRITICAL"
        if "ERROR" in msg or "ERR" in msg or "FAILED" in msg or "FAIL" in msg:
            # Check if it is a common auth failure or crash
            return "ERROR"
        if "WARNING" in msg or "WARN" in msg or "UNAUTHORIZED" in msg:
            return "WARNING"
        if "DEBUG" in msg:
            return "DEBUG"
        
        return "INFO"
