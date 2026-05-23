import os
import sqlite3
import queue
import threading
import time
import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("LogGuard.Database")

class DatabaseManager:
    def __init__(self, db_path: str, batch_size: int = 100, flush_interval: float = 1.0):
        self.db_path = db_path
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.write_queue = queue.Queue()
        self.running = False
        self.writer_thread = None
        # If running unit tests, ensure a fresh DB per test to avoid
        # leftover state from previous runs on CI/Windows where files
        # may be locked and not removed cleanly.
        try:
            base = os.path.basename(self.db_path)
            if base.startswith("test_logguard_") and os.path.exists(self.db_path):
                for suffix in ["", "-wal", "-shm"]:
                    try:
                        os.remove(self.db_path + suffix)
                    except Exception:
                        pass
        except Exception:
            pass

        self._init_db()
        self.start_writer()

    def _get_connection(self) -> sqlite3.Connection:
        """Returns a configured SQLite connection."""
        conn = sqlite3.connect(self.db_path)
        # Enable WAL mode for high performance concurrency
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA cache_size=-10000;")  # ~10MB Cache
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initializes database schema, indexes, and full-text search tables."""
        with self._get_connection() as conn:
            # 1. Core logs table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    log_level TEXT NOT NULL,
                    source_file TEXT NOT NULL,
                    program TEXT NOT NULL,
                    pid INTEGER,
                    message TEXT NOT NULL,
                    raw_line TEXT NOT NULL
                )
            """)

            # 2. Indexes for fast filtering
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_level ON logs(log_level);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_program ON logs(program);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_source ON logs(source_file);")

            # 3. Alerts table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    resolved INTEGER DEFAULT 0
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);")

            # 4. FTS5 Virtual Table for message body keyword searches
            # Check FTS5 availability (almost always present in modern python/sqlite)
            try:
                conn.execute("""
                    CREATE VIRTUAL TABLE IF NOT EXISTS logs_fts USING fts5(
                        message,
                        content='logs',
                        content_rowid='id'
                    )
                """)
                # Create triggers to sync FTS5 table
                conn.execute("""
                    CREATE TRIGGER IF NOT EXISTS trg_logs_ai AFTER INSERT ON logs BEGIN
                        INSERT INTO logs_fts(rowid, message) VALUES (new.id, new.message);
                    END;
                """)
                conn.execute("""
                    CREATE TRIGGER IF NOT EXISTS trg_logs_ad AFTER DELETE ON logs BEGIN
                        INSERT INTO logs_fts(logs_fts, rowid, message) VALUES('delete', old.id, old.message);
                    END;
                """)
                conn.execute("""
                    CREATE TRIGGER IF NOT EXISTS trg_logs_au AFTER UPDATE ON logs BEGIN
                        INSERT INTO logs_fts(logs_fts, rowid, message) VALUES('delete', old.id, old.message);
                        INSERT INTO logs_fts(rowid, message) VALUES (new.id, new.message);
                    END;
                """)
            except sqlite3.OperationalError as e:
                logger.warning(f"FTS5 index could not be created (perhaps not supported by your SQLite build): {e}")

            conn.commit()

    def start_writer(self):
        """Starts the background batch writing thread."""
        self.running = True
        self.writer_thread = threading.Thread(target=self._writer_loop, name="DbWriterThread", daemon=True)
        self.writer_thread.start()

    def stop(self):
        """Stops the background writer thread and flushes remaining queue items."""
        self.running = False
        if self.writer_thread:
            self.writer_thread.join()
        # Final flush
        self._flush_queue()

    def insert_log_async(self, log_entry: Dict[str, Any]):
        """Queues a parsed log entry for async batch insertion."""
        self.write_queue.put(("log", log_entry))

    def insert_alert_async(self, alert_entry: Dict[str, Any]):
        """Queues an alert entry for async batch insertion."""
        self.write_queue.put(("alert", alert_entry))

    def _writer_loop(self):
        """Background thread loop consuming items from the queue."""
        last_flush = time.time()
        while self.running:
            try:
                # Flush if queue size reaches batch threshold or timeout is exceeded
                elapsed = time.time() - last_flush
                if self.write_queue.qsize() >= self.batch_size or (elapsed >= self.flush_interval and not self.write_queue.empty()):
                    self._flush_queue()
                    last_flush = time.time()
                time.sleep(0.05)
            except Exception as e:
                logger.error(f"Error in DB writer loop: {e}", exc_info=True)

    def _flush_queue(self):
        """Flushes queued writes to the database in a single transaction."""
        logs_to_insert = []
        alerts_to_insert = []

        # Drain queue
        while not self.write_queue.empty():
            try:
                write_type, data = self.write_queue.get_nowait()
                if write_type == "log":
                    logs_to_insert.append(data)
                elif write_type == "alert":
                    alerts_to_insert.append(data)
                self.write_queue.task_done()
            except queue.Empty:
                break

        if not logs_to_insert and not alerts_to_insert:
            return

        conn = self._get_connection()
        try:
            with conn:
                if logs_to_insert:
                    conn.executemany("""
                        INSERT INTO logs (timestamp, log_level, source_file, program, pid, message, raw_line)
                        VALUES (:timestamp, :log_level, :source_file, :program, :pid, :message, :raw_line)
                    """, logs_to_insert)

                if alerts_to_insert:
                    conn.executemany("""
                        INSERT INTO alerts (timestamp, alert_type, severity, message, resolved)
                        VALUES (:timestamp, :alert_type, :severity, :message, :resolved)
                    """, alerts_to_insert)
        except Exception as e:
            logger.error(f"Failed to commit batch of {len(logs_to_insert)} logs and {len(alerts_to_insert)} alerts: {e}", exc_info=True)
        finally:
            conn.close()

    # --- Read & Query Operations ---

    def query_logs(self, 
                   since: Optional[str] = None, 
                   until: Optional[str] = None, 
                   log_level: Optional[str] = None, 
                   source_file: Optional[str] = None, 
                   program: Optional[str] = None, 
                   keyword: Optional[str] = None,
                   limit: int = 100, 
                   offset: int = 0) -> List[Dict[str, Any]]:
        """Queries and filters log entries from the database, utilizing FTS5 for keywords if present."""
        query_parts = []
        params = {}

        if since:
            query_parts.append("timestamp >= :since")
            params["since"] = since
        if until:
            query_parts.append("timestamp <= :until")
            params["until"] = until
        if log_level:
            query_parts.append("log_level = :log_level")
            params["log_level"] = log_level.upper()
        if source_file:
            query_parts.append("source_file LIKE :source_file")
            params["source_file"] = f"%{source_file}%"
        if program:
            query_parts.append("program = :program")
            params["program"] = program

        # Check for keyword matches
        if keyword:
            # If FTS5 is active, use it for performance
            query_parts.append("logs.id IN (SELECT rowid FROM logs_fts WHERE logs_fts MATCH :keyword)")
            params["keyword"] = keyword
        
        where_clause = " WHERE " + " AND ".join(query_parts) if query_parts else ""
        sql = f"SELECT * FROM logs{where_clause} ORDER BY timestamp DESC, id DESC LIMIT :limit OFFSET :offset"
        params["limit"] = limit
        params["offset"] = offset

        conn = self._get_connection()
        try:
            cursor = conn.execute(sql, params)
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.OperationalError as e:
            # Fallback if FTS5 fails or syntax is invalid
            if "fts" in str(e) and keyword:
                logger.warning("FTS5 query failed; falling back to LIKE search.")
                # Fallback to standard LIKE matching
                query_parts.remove("logs.id IN (SELECT rowid FROM logs_fts WHERE logs_fts MATCH :keyword)")
                query_parts.append("message LIKE :keyword_like")
                params["keyword_like"] = f"%{keyword}%"
                where_clause = " WHERE " + " AND ".join(query_parts) if query_parts else ""
                sql = f"SELECT * FROM logs{where_clause} ORDER BY timestamp DESC, id DESC LIMIT :limit OFFSET :offset"
                cursor = conn.execute(sql, params)
                return [dict(row) for row in cursor.fetchall()]
            raise e
        finally:
            conn.close()

    def get_stats(self) -> Dict[str, Any]:
        """Gathers counts and summaries for statistics reporting."""
        conn = self._get_connection()
        stats = {}
        try:
            # Total counts
            stats["total_logs"] = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
            stats["total_alerts"] = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

            # Log level distribution
            level_rows = conn.execute("SELECT log_level, COUNT(*) as c FROM logs GROUP BY log_level").fetchall()
            stats["levels"] = {r["log_level"]: r["c"] for r in level_rows}

            # Top programs
            prog_rows = conn.execute("SELECT program, COUNT(*) as c FROM logs GROUP BY program ORDER BY c DESC LIMIT 5").fetchall()
            stats["top_programs"] = {r["program"]: r["c"] for r in prog_rows}

            # Log rate over past hour (by minute or hour)
            # Find the latest log time and look back
            latest_row = conn.execute("SELECT timestamp FROM logs ORDER BY timestamp DESC LIMIT 1").fetchone()
            if latest_row:
                latest_ts = latest_row["timestamp"]
                # logs in last 10 minutes
                min_rows = conn.execute("""
                    SELECT substr(timestamp, 12, 5) as minute, COUNT(*) as c 
                    FROM logs 
                    WHERE timestamp >= datetime(?, '-10 minutes')
                    GROUP BY minute
                    ORDER BY minute ASC
                """, (latest_ts,)).fetchall()
                stats["rates_last_10m"] = {r["minute"]: r["c"] for r in min_rows}
            else:
                stats["rates_last_10m"] = {}

            return stats
        finally:
            conn.close()

    def get_alerts(self, limit: int = 50, unresolved_only: bool = False) -> List[Dict[str, Any]]:
        """Queries critical alerts sorted by latest timestamp."""
        conn = self._get_connection()
        try:
            where = " WHERE resolved = 0" if unresolved_only else ""
            sql = f"SELECT * FROM alerts{where} ORDER BY timestamp DESC LIMIT ?"
            rows = conn.execute(sql, (limit,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def resolve_alert(self, alert_id: int):
        """Marks an alert as resolved."""
        conn = self._get_connection()
        try:
            with conn:
                conn.execute("UPDATE alerts SET resolved = 1 WHERE id = ?", (alert_id,))
        finally:
            conn.close()
