import sqlite3

path = 'test_logguard_test_log_insertion_and_query.db'
conn=sqlite3.connect(path)
conn.row_factory=sqlite3.Row
cur=conn.cursor()
print('tables:', [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()])
print('logs count:', cur.execute('SELECT COUNT(*) FROM logs').fetchone()[0])
for row in cur.execute('SELECT id,timestamp,log_level,program,message FROM logs ORDER BY id'): print(dict(row))
print('alerts count:', cur.execute('SELECT COUNT(*) FROM alerts').fetchone()[0])
try:
    print('fts count:', cur.execute('SELECT COUNT(*) FROM logs_fts').fetchone()[0])
except Exception as e:
    print('no fts:', e)
conn.close()
