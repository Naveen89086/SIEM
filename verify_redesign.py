import sqlite3
import os
import sys

DB_PATH = 'siem.db'

def verify_redesign():
    print("[+] Starting Verification...")
    
    if not os.path.exists(DB_PATH):
        print(f"❌ FAILURE: Database {DB_PATH} not found.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        # 1. Verify table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='security_logs'")
        if cursor.fetchone():
            print("✅ SUCCESS: security_logs table exists.")
        else:
            print("❌ FAILURE: security_logs table missing.")
            return

        # 2. Verify columns
        cursor.execute("PRAGMA table_info(security_logs)")
        columns = {row[1] for row in cursor.fetchall()}
        required_columns = {'id', 'timestamp', 'src_ip', 'dst_ip', 'protocol', 'port', 'alert_type', 'severity', 'description', 'details'}
        
        missing = required_columns - columns
        if not missing:
            print("✅ SUCCESS: All required columns are present.")
        else:
            print(f"❌ FAILURE: Missing columns: {missing}")

        # 3. Verify data migration
        cursor.execute("SELECT COUNT(*) FROM security_logs")
        count = cursor.fetchone()[0]
        print(f"[i] Total records in security_logs: {count}")
        if count > 0:
            print("✅ SUCCESS: Data exists in security_logs.")
        else:
            print("❌ WARNING: security_logs is empty.")

        # 4. Verify insertion via database.py
        sys.path.append(os.getcwd())
        from database import insert_event, search_security_logs
        
        test_msg = "VERIFICATION_TEST_ALERT"
        insert_event("DEBUG", test_msg, {"protocol": "TCP", "port": "9999"}, "LOW", src_ip="1.1.1.1", dst_ip="2.2.2.2")
        
        results = search_security_logs(search=test_msg)
        if results and results[0]['description'] == test_msg:
            print("✅ SUCCESS: New log insertion and retrieval verified.")
            print(f"    Details: {results[0]['protocol']}:{results[0]['port']}")
        else:
            print("❌ FAILURE: Could not retrieve recently inserted test log.")

    except Exception as e:
        print(f"❌ ERROR: Verification failed with: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    verify_redesign()
