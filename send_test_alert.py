import datetime
import json
from alert_email import send_email, get_html_template

def send_test_alert():
    print("--- SIEM Test Email Alert ---")
    
    # Mock data for the test alert
    severity = "CRITICAL"
    event_type = "TEST_ALRERT"
    mitre_id = "T1234"
    mitre_tactic = "Antigravity Test"
    message = "This is a TEST alert sent from the SIEM system to verify email notification functionality."
    src_ip = "127.0.0.1"
    dst_ip = "10.0.0.5"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    details = {
        "test_mode": True,
        "purpose": "Verification of professional HTML email alerts",
        "timestamp_iso": datetime.datetime.now().isoformat()
    }

    print(f"Generating template for severity: {severity}...")
    html_body = get_html_template(
        severity, event_type, mitre_id, mitre_tactic, message, src_ip, dst_ip, timestamp, details
    )
    
    subject = f"🛡️ [TEST] SIEM ALERT: {severity} - {event_type}"
    plain_body = f"TEST ALERT\nSeverity: {severity}\nType: {event_type}\nMessage: {message}\nTime: {timestamp}"

    print(f"Sending email to configured recipient...")
    send_email(subject, plain_body, html_body)
    print("Done. Please check your inbox.")

if __name__ == "__main__":
    send_test_alert()
