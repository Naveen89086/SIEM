import sys
import os
import time

# Ensure the current directory is in the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from mongodb_storage import atlas_client, insert_log_to_atlas
from config import MONGODB_URI

def test_connection():
    print("--- SIEM MongoDB Atlas Connection Test ---")
    
    if "<db_username>" in MONGODB_URI:
        print("\n❌ ERROR: You haven't configured your MongoDB URI yet!")
        print("Please open 'config.py' and replace the placeholder MONGODB_URI with your Atlas connection string.")
        return

    print(f"Connecting to: {MONGODB_URI.split('@')[-1] if '@' in MONGODB_URI else 'Unknown'}")
    
    if atlas_client.connect():
        print("✅ SUCCESS: Connected to MongoDB Atlas!")
        
        print("\nSending test security log...")
        event_id = insert_log_to_atlas(
            event_type="TEST_CONNECTION",
            message="Initial test log from SIEM project",
            severity="LOW",
            details={"test": True, "note": "If you see this, Atlas integration is working!"}
        )
        
        if event_id:
            print(f"✅ SUCCESS: Log stored in Atlas! Document ID: {event_id}")
            print("\nCheck your MongoDB Atlas dashboard -> Collections to see the log.")
        else:
            print("❌ FAILED: Could not store log in Atlas.")
    else:
        print("❌ FAILED: Could not connect to MongoDB Atlas.")
        print("Check your URI, database username/password, and Network Access (IP Whitelist) in Atlas.")

if __name__ == "__main__":
    test_connection()
