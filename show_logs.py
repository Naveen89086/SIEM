import sqlite3
import os

DB_PATH = 'siem.db'

def show_logs():
    if not os.path.exists(DB_PATH):
        print(f"Database {DB_PATH} not found.")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT * FROM security_logs ORDER BY timestamp DESC LIMIT 10")
        rows = cursor.fetchall()

        if not rows:
            print("No logs found in security_logs table.")
            return

        # Print header
        header = f"{'ID':<4} | {'Timestamp':<20} | {'Src IP':<15} | {'Protocol':<8} | {'Port':<6} | {'Alert Type':<15} | {'Severity':<8}"
        print(header)
        print("-" * len(header))

        for row in rows:
            import time
            ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(row['timestamp']))
            print(f"{row['id']:<4} | {ts:<20} | {row['src_ip']:<15} | {row['protocol']:<8} | {row['port']:<6} | {row['alert_type']:<15} | {row['severity']:<8}")
            print(f"     Description: {row['description']}")
            print("-" * len(header))

    except Exception as e:
        print(f"Error querying database: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    show_logs()
