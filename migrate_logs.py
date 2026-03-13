import sqlite3
import json
import os

DB_PATH = 'siem.db'

def migrate_data():
    if not os.path.exists(DB_PATH):
        print(f"Database {DB_PATH} not found.")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        # Check if events table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events'")
        if not cursor.fetchone():
            print("Events table not found. Nothing to migrate.")
            return

        # Fetch all events
        cursor.execute("SELECT * FROM events")
        events = cursor.fetchall()
        print(f"Found {len(events)} events to migrate.")

        for ev in events:
            details_str = ev['details']
            details = {}
            try:
                details = json.loads(details_str)
            except:
                pass

            protocol = details.get('protocol', '')
            port = details.get('port', details.get('dst_port', details.get('target_port', '')))
            
            cursor.execute("""
                INSERT INTO security_logs 
                (timestamp, src_ip, dst_ip, protocol, port, alert_type, severity, description, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ev['timestamp'],
                ev['src_ip'],
                ev['dst_ip'],
                protocol,
                str(port),
                ev['event_type'],
                ev['severity'],
                ev['message'],
                details_str
            ))
        
        conn.commit()
        print("Migration completed successfully.")

    except Exception as e:
        print(f"Error during migration: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_data()
