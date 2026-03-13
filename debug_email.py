import smtplib
import ssl
from config import EMAIL_FROM, EMAIL_TO, EMAIL_PASSWORD, SMTP_SERVER, SMTP_PORT

print(f"DEBUG: EMAIL_FROM={EMAIL_FROM}")
print(f"DEBUG: EMAIL_TO={EMAIL_TO}")
print(f"DEBUG: PASSWORD LENGTH={len(EMAIL_PASSWORD)}")
print(f"DEBUG: PASSWORD='{EMAIL_PASSWORD}'") # BE CAREFUL LOGGING THIS, BUT LOCALLY OK FOR DEBUG

context = ssl.create_default_context()

print("\nAttempting SMTP_SSL (Port 465)...")
try:
    with smtplib.SMTP_SSL(SMTP_SERVER, 465, context=context) as server:
        server.login(EMAIL_FROM, EMAIL_PASSWORD)
        server.sendmail(EMAIL_FROM, EMAIL_TO, "Subject: Test\n\nTest")
        print("SUCCESS with SMTP_SSL")
except Exception as e:
    print(f"FAIL with SMTP_SSL: {e}")

print("\nAttempting SMTP + STARTTLS (Port 587)...")
try:
    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls(context=context)
        server.login(EMAIL_FROM, EMAIL_PASSWORD)
        server.sendmail(EMAIL_FROM, EMAIL_TO, "Subject: Test\n\nTest")
        print("SUCCESS with STARTTLS")
except Exception as e:
    print(f"FAIL with STARTTLS: {e}")
