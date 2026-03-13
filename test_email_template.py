from alert_email import get_html_template

# Mock data
severity = "CRITICAL"
event_type = "DATA_EXFIL"
mitre_id = "T1048"
mitre_tactic = "Exfiltration"
message = "Possible Data Exfiltration detected from 10.37.83.209 (5.0MB sent in 120s)"
src_ip = "10.37.83.209"
dst_ip = "192.168.1.100"
timestamp = "2026-02-13 21:45:00"
details = {"bytes_sent": 5242880, "window": 120, "threshold": 5000000}

html = get_html_template(severity, event_type, mitre_id, mitre_tactic, message, src_ip, dst_ip, timestamp, details)

print("Generated HTML Length:", len(html))
print("HTML Preview (First 500 chars):")
print(html[:500])

with open("email_preview.html", "w", encoding="utf-8") as f:
    f.write(html)
print("\n[SUCCESS] Preview saved to email_preview.html")
