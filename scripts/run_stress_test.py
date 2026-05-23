import os
import time
from src.database import DatabaseManager

def run_stress_test():
    db_path = "stress_test.db"
    
    # 1. Clean up old databases
    for file in [db_path, f"{db_path}-wal", f"{db_path}-shm"]:
        if os.path.exists(file):
            os.remove(file)

    print("================================================================")
    print("                LogGuard Ingestion Stress Test                  ")
    print("================================================================")
    
    # 2. Setup Database Manager
    # Configuring with 2000 batch size and short timeout for heavy inserts
    db = DatabaseManager(db_path, batch_size=2000, flush_interval=0.05)
    
    num_records = 100000
    print(f"Generating {num_records} test log entries in memory...")
    
    # Pre-build logs to isolate DB write speed measurements
    test_logs = []
    for i in range(num_records):
        test_logs.append({
            "timestamp": "2026-05-24 01:40:15",
            "log_level": "INFO",
            "source_file": "Stress Test Log",
            "program": "load-test-agent",
            "pid": 9999,
            "message": f"Stress test message sequence indicator: log #{i}",
            "raw_line": f"May 24 01:40:15 srv load-test-agent[9999]: Stress test message sequence indicator: log #{i}"
        })

    print("Beginning bulk ingestion...")
    start_time = time.time()
    
    for log in test_logs:
        db.insert_log_async(log)
        
    print("All logs queued. Waiting for queue flush...")
    # Block and wait for queue to empty
    while not db.write_queue.empty():
        time.sleep(0.01)
        
    # Final force flush to ensure clean commit
    db._flush_queue()
    end_time = time.time()
    
    duration = end_time - start_time
    rate = num_records / duration
    
    print("\n------------------------- Results ------------------------------")
    print(f"Total Logs Ingested:   {num_records} logs")
    print(f"Total Write Time:      {duration:.2f} seconds")
    print(f"Ingestion Throughput:  {rate:.2f} inserts/second")
    print("----------------------------------------------------------------")

    # 3. Stop database threads and commit everything
    db.stop()

    # Verify counts in DB
    stats = db.get_stats()
    print(f"Verified Database Count: {stats['total_logs']} logs in logs table")
    
    # Run a quick FTS search to verify indices
    print("Testing Full-Text FTS5 index speed...")
    fts_start = time.time()
    results = db.query_logs(keyword="sequence", limit=10)
    fts_end = time.time()
    print(f"FTS5 Query took: {(fts_end - fts_start)*1000:.3f} milliseconds (Returned {len(results)} samples)")

    
    # Remove files
    for file in [db_path, f"{db_path}-wal", f"{db_path}-shm"]:
        if os.path.exists(file):
            try:
                os.remove(file)
            except Exception:
                pass
                
    print("Stress test completed and temp database cleaned up.")
    print("================================================================")

if __name__ == "__main__":
    run_stress_test()
