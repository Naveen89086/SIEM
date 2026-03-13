from alert_email import send_email
from config import EMAIL_TO

print(f"Attempting to send test email to {EMAIL_TO}...")
try:
    send_email("Test Subject", "Test Body")
    print("Test email sent successfully!")
except Exception as e:
    print(f"Failed to send test email: {e}")
