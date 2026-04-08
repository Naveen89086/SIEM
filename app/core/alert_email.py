import smtplib
import json
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from app.config import EMAIL_FROM, EMAIL_TO, EMAIL_PASSWORD, SMTP_SERVER, SMTP_PORT, BASE_URL

def get_html_template(severity, event_type, mitre_id, mitre_tactic, message, src_ip, dst_ip, timestamp, details):
    """Generates a professional SOC-branded HTML email template."""
    colors = {
        "CRITICAL": "#ff3366",
        "HIGH": "#ff9933",
        "MEDIUM": "#fbbf24",
        "LOW": "#00cc99"
    }
    header_color = colors.get(severity, "#1e293b")
    details_str = json.dumps(details, indent=2) if details else "{}"
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ font-family: 'Inter', Helvetica, Arial, sans-serif; background-color: #f4f7f9; color: #1e293b; margin: 0; padding: 0; }}
            .container {{ max-width: 600px; margin: 20px auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
            .header {{ background-color: {header_color}; color: #ffffff; padding: 30px; text-align: center; }}
            .header h1 {{ margin: 0; font-size: 24px; letter-spacing: -0.5px; font-weight: 800; }}
            .header p {{ margin: 5px 0 0; opacity: 0.9; font-size: 14px; font-weight: 600; text-transform: uppercase; }}
            .content {{ padding: 30px; }}
            .status-box {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin-bottom: 25px; }}
            .status-row {{ display: flex; border-bottom: 1px solid #edf2f7; padding: 10px 0; }}
            .status-row:last-child {{ border-bottom: none; }}
            .label {{ font-weight: 700; width: 140px; color: #64748b; font-size: 13px; text-transform: uppercase; }}
            .value {{ flex: 1; font-weight: 600; color: #1e293b; font-size: 14px; word-break: break-all; }}
            .msg-box {{ background: #fffbe6; border-left: 4px solid #fbbf24; padding: 15px; margin: 20px 0; font-weight: 500; font-size: 15px; line-height: 1.6; color: #856404; }}
            {f'.msg-box {{ border-left-color: {header_color}; background-color: {header_color}10; color: {header_color}; }}' if severity in ['HIGH', 'CRITICAL'] else ''}
            .btn {{ display: inline-block; padding: 14px 28px; background-color: #00d4ff; color: #ffffff !important; text-decoration: none; border-radius: 8px; font-weight: 700; margin-top: 20px; text-align: center; }}
            .footer {{ background-color: #f8fafc; padding: 20px; text-align: center; font-size: 12px; color: #94a3b8; }}
            .code-block {{ font-family: 'JetBrains Mono', Courier, monospace; background: #0f172a; color: #e2e8f0; padding: 15px; border-radius: 8px; font-size: 12px; overflow-x: auto; margin-top: 10px; }}
            
            @media screen and (max-width: 600px) {{
                .container {{ margin: 0; border-radius: 0; }}
                .status-row {{ display: block; }}
                .label {{ width: 100%; margin-bottom: 4px; }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ SOC SIEM ALERT</h1>
                <p>{severity} SEVERITY DETECTED</p>
            </div>
            <div class="content">
                <div class="status-box">
                    <div class="status-row">
                        <div class="label">Attack Type</div>
                        <div class="value">{event_type}</div>
                    </div>
                    <div class="status-row">
                        <div class="label">MITRE ID</div>
                        <div class="value">{mitre_id if mitre_id else "N/A"}</div>
                    </div>
                    <div class="status-row">
                        <div class="label">MITRE Tactic</div>
                        <div class="value">{mitre_tactic if mitre_tactic else "N/A"}</div>
                    </div>
                    <div class="status-row">
                        <div class="label">Source IP</div>
                        <div class="value" style="font-family: monospace;">{src_ip if src_ip else "Unknown"}</div>
                    </div>
                    <div class="status-row">
                        <div class="label">Target IP</div>
                        <div class="value" style="font-family: monospace;">{dst_ip if dst_ip else "Internal Host"}</div>
                    </div>
                    <div class="status-row">
                        <div class="label">Detection Time</div>
                        <div class="value">{timestamp}</div>
                    </div>
                </div>

                <h3>Description</h3>
                <div class="msg-box">
                    {message}
                </div>

                <h3>Technical Details</h3>
                <div class="code-block">
                    <pre style="margin:0; white-space: pre-wrap; word-break: break-all;">{details_str}</pre>
                </div>

                <div style="text-align: center;">
                    <a href="{BASE_URL}" class="btn">ENTER COMMAND CENTER</a>
                </div>
            </div>
            <div class="footer">
                <p>This is an automated security alert from your SIEM Pro engine.</p>
                <p>&copy; 2026 SOC Command Center | Managed Endpoint Defense</p>
                <p>Accessible via: {BASE_URL}</p>
            </div>
        </div>
    </body>
    </html>
    """
    return html

def send_email(subject, body, html_body=None):
    """Sends a professional MIMEMultipart email."""
    if not EMAIL_PASSWORD or not EMAIL_FROM:
        print("[WARN] Email not configured. Skipping email alert.")
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = EMAIL_TO

    msg.attach(MIMEText(body, "plain"))
    if html_body:
        msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(EMAIL_FROM, EMAIL_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        print(f"[ERROR] Failed to send email alert: {e}")
