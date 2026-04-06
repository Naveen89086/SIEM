import sys
import os

# Add current dir to path
sys.path.append(os.getcwd())

from database import init_db, insert_event, get_last_log_hash
import time

def test_db():
    print("Initializing DB...")
    init_db()
    
    print(f"Current last hash: {get_last_log_hash()}")
    
    print("Inserting test event...")
    event_id = insert_event(
        event_type="TEST_ALERT",
        message="Manual verification event",
        severity="HIGH",
        src_ip="1.2.3.4",
        dst_ip="8.8.8.8",
        protocol="TCP",
        port=443
    )
    print(f"Inserted event ID: {event_id}")
    
    print(f"New last hash: {get_last_log_hash()}")

if __name__ == "__main__":
    test_db()
