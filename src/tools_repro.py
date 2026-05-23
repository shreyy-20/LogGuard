from src.database import DatabaseManager
import os

def main():
    path = 'tools_test.db'
    if os.path.exists(path):
        for s in ['', '-wal', '-shm']:
            p = path + s
            if os.path.exists(p):
                os.remove(p)

    db = DatabaseManager(path, batch_size=10, flush_interval=0.1)
    entry = {
        "timestamp": "2026-05-24 01:40:15",
        "log_level": "ERROR",
        "source_file": "System Log",
        "program": "sshd",
        "pid": 1234,
        "message": "Failed connection attempt",
        "raw_line": "line"
    }

    db.insert_log_async(entry)
    db._flush_queue()
    results = db.query_logs(log_level='ERROR')
    print('Count after first flush:', len(results))

    db.insert_log_async(entry)
    db._flush_queue()
    results = db.query_logs(log_level='ERROR')
    print('Count after second flush:', len(results))

    db.stop()
    for s in ['', '-wal', '-shm']:
        p = path + s
        if os.path.exists(p):
            os.remove(p)

if __name__ == '__main__':
    main()
