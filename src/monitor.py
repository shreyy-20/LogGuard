import os
import time
import threading
import logging
from typing import List, Callable, Dict, Optional, Tuple

logger = logging.getLogger("LogGuard.Monitor")

class LogFileTailer:
    """Tails a single log file, handling log rotation and file truncation."""
    def __init__(self, file_path: str, callback: Callable[[str, str], None], poll_interval: float = 0.5):
        self.file_path = file_path
        self.callback = callback
        self.poll_interval = poll_interval
        self.running = False
        self.thread = None
        self.last_inode = None
        self.last_size = 0

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._tail_loop, name=f"Tail-{os.path.basename(self.file_path)}", daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()

    def _get_file_info(self) -> Tuple[Optional[int], Optional[int]]:
        """Returns (inode, size) of the file if it exists, otherwise (None, None)."""
        try:
            stat_res = os.stat(self.file_path)
            # Inode is only meaningful on POSIX, but os.stat returns it on all platforms (0 on some Windows configs)
            # On Windows, we can use creation time as a pseudo-inode if st_ino is 0
            inode = stat_res.st_ino if stat_res.st_ino != 0 else int(stat_res.st_ctime)
            return inode, stat_res.st_size
        except FileNotFoundError:
            return None, None

    def _tail_loop(self):
        logger.info(f"Started tailing thread for: {self.file_path}")
        f = None

        while self.running:
            # 1. Check if file exists
            inode, size = self._get_file_info()
            if inode is None:
                # File doesn't exist yet, wait and retry
                if f:
                    logger.warning(f"File vanished, closing handle: {self.file_path}")
                    f.close()
                    f = None
                time.sleep(self.poll_interval)
                continue

            # 2. Check for rotation/truncation
            rotated = False
            if f is None:
                # First open
                try:
                    # Open at end of file initially to avoid dumping massive backlogs,
                    # unless file size is small.
                    f = open(self.file_path, "r", encoding="utf-8", errors="ignore")
                    f.seek(0, os.SEEK_END)
                    self.last_inode = inode
                    self.last_size = size
                except Exception as e:
                    logger.error(f"Error opening file {self.file_path}: {e}")
                    time.sleep(self.poll_interval)
                    continue
            else:
                # Check if file rotated (different inode/creation time) or was truncated (size smaller)
                if inode != self.last_inode:
                    logger.info(f"Log rotation detected for {self.file_path} (inode changed: {self.last_inode} -> {inode})")
                    rotated = True
                elif size < self.last_size:
                    logger.info(f"File truncation detected for {self.file_path} (size shrunk: {self.last_size} -> {size})")
                    rotated = True

            if rotated:
                f.close()
                try:
                    f = open(self.file_path, "r", encoding="utf-8", errors="ignore")
                    # Start reading from beginning of the new file
                    self.last_inode = inode
                    self.last_size = size
                except Exception as e:
                    logger.error(f"Error reopening rotated file {self.file_path}: {e}")
                    f = None
                    time.sleep(self.poll_interval)
                    continue

            # 3. Read any new lines
            try:
                current_pos = f.tell()
                lines = f.readlines()
                if lines:
                    for line in lines:
                        self.callback(line, self.file_path)
                    self.last_size = os.path.getsize(self.file_path)
                else:
                    # Check if file size grew but readlines returned nothing (e.g. partial writes)
                    # We just update our last_size record
                    self.last_size = size
            except Exception as e:
                logger.error(f"Error reading from {self.file_path}: {e}")
                time.sleep(self.poll_interval)
                continue

            time.sleep(self.poll_interval)

        if f:
            f.close()
            logger.info(f"Stopped tailing: {self.file_path}")

class LogMonitor:
    """Manages tailers for multiple log files."""
    def __init__(self, file_paths: List[str], callback: Callable[[str, str], None], poll_interval: float = 0.5):
        self.file_paths = file_paths
        self.callback = callback
        self.poll_interval = poll_interval
        self.tailers: Dict[str, LogFileTailer] = {}

    def start(self):
        """Starts tailing all specified files."""
        for path in self.file_paths:
            # Create logs folder if it doesn't exist
            dir_name = os.path.dirname(path)
            if dir_name and not os.path.exists(dir_name):
                os.makedirs(dir_name, exist_ok=True)
                
            tailer = LogFileTailer(path, self.callback, self.poll_interval)
            tailer.start()
            self.tailers[path] = tailer
        logger.info(f"LogMonitor active. Tailing {len(self.file_paths)} files.")

    def stop(self):
        """Stops tailing all files."""
        for path, tailer in self.tailers.items():
            tailer.stop()
        self.tailers.clear()
        logger.info("LogMonitor stopped.")
