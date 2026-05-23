import os
import sys
import time
import unittest
from src.monitor import LogFileTailer

class TestLogFileTailer(unittest.TestCase):
    def setUp(self):
        self.test_file = "test_tail.log"
        self.received_lines = []
        
        # Callback to collect tailed lines
        def tail_callback(line, file_path):
            self.received_lines.append(line.strip())
            
        # Create initial file with long string to guarantee truncation size shrinkage
        with open(self.test_file, "w", encoding="utf-8") as f:
            f.write("initial line 1 with dummy text to make the file size larger than 100 bytes so that a truncation is easily detected\n")
            
        # Set up tailer with 0.05s polling for fast test cycles
        self.tailer = LogFileTailer(self.test_file, tail_callback, poll_interval=0.05)
        self.tailer.start()
        # Wait a moment for thread to initialize and position file pointer at EOF
        time.sleep(0.1)

    def tearDown(self):
        self.tailer.stop()
        if os.path.exists(self.test_file):
            try:
                os.remove(self.test_file)
            except Exception:
                pass

    def test_line_tailing(self):
        """Verifies lines appended to file are read in real-time."""
        with open(self.test_file, "a", encoding="utf-8") as f:
            f.write("new line 2\n")
            f.write("new line 3\n")

        # Wait for poll interval
        time.sleep(0.15)
        self.assertEqual(len(self.received_lines), 2)
        self.assertEqual(self.received_lines[0], "new line 2")
        self.assertEqual(self.received_lines[1], "new line 3")

    def test_file_truncation(self):
        """Verifies tailer handles truncation (file size shrinking) and reads from start."""
        # Truncate and write new content
        with open(self.test_file, "w", encoding="utf-8") as f:
            f.write("truncated line 1\n")

        time.sleep(0.15)
        self.assertEqual(len(self.received_lines), 1)
        self.assertEqual(self.received_lines[0], "truncated line 1")

    @unittest.skipIf(sys.platform == "win32", "Windows locks open files, preventing rotation testing while handle is active")
    def test_file_rotation(self):
        """Verifies tailer handles file deletion and recreation."""
        # Delete file
        os.remove(self.test_file)
        time.sleep(0.15) # Allow tailer to notice missing file

        # Recreate file
        with open(self.test_file, "w", encoding="utf-8") as f:
            f.write("recreated line 1\n")

        time.sleep(0.15)
        self.assertEqual(len(self.received_lines), 1)
        self.assertEqual(self.received_lines[0], "recreated line 1")

if __name__ == "__main__":
    unittest.main()
