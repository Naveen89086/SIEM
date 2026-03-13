import sqlite3
import os
import sys

# Add current dir to path to import local modules
sys.path.append(os.getcwd())

def check_alerts():
    print("--- Searching for HIGH/CRITICAL Alerts in Database ---")
    try:
        conn = sqlite3.connect('siem.db')
        curr = conn.cursor()
        curr.execute('SELECT severity, alert_type, timestamp, description FROM security_logs WHERE severity IN ("HIGH", "CRITICAL") ORDER BY timestamp DESC LIMIT 5')
        rows = curr.fetchall()
        if not rows:
            print("No high or critical alerts found in the database. (Email only triggers for High/Critical)")
        for row in rows:
            print(f"[{row[0]}] {row[1]} @ {row[2]}: {row[3][:50]}...")
        conn.close()
    except Exception as e:
        print(f"Error checking database: {e}")

def test_email():
    print("\n--- Attempting Test Email with Current Config ---")
    try:
        from alert_email import send_email
        from config import EMAIL_TO
        subject = "🧪 SIEM Diagnostic: Test Alert"
        body = "This is a diagnostic test to verify that the SIEM email alerting system is working correctly with your new password."
        html = "<h1>SIEM Diagnostic</h1><p>The email system is successfully communicating with the SMTP server.</p>"
        
        print(f"Sending test email to: {EMAIL_TO}...")
        send_email(subject, body, html_body=html)
        print("Success! If you don't see it in your Inbox, check your SPAM folder.")
    except Exception as e:
        print(f"Failed to send test email: {e}")

if __name__ == "__main__":
    check_alerts()
    test_email()
