import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

SMTP_EMAIL = "ankesh.kushwah139426@marwadiuniversity.ac.in"
SMTP_PASSWORD = "wwpe becy gljx ooqc"
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587

def test_email_connection():
    try:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        server.starttls()
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.quit()
        return {"connected": True, "message": "Email works! ✅"}
    except Exception as e:
        return {"connected": False, "error": str(e)}

def send_breach_alert(to_email: str, breach_data: dict):
    analysis = breach_data.get("analysis", {})
    total = analysis.get("total_breaches", 0)
    risk = analysis.get("overall_risk", 0)
    severity = analysis.get("severity", "UNKNOWN")
    fields = analysis.get("all_leaked_fields", [])
    ai_advice = breach_data.get("ai_advice", "")

    if severity == "CRITICAL":
        color_code = "#ff0000"
    elif severity == "HIGH":
        color_code = "#ff6600"
    elif severity == "MEDIUM":
        color_code = "#ffaa00"
    else:
        color_code = "#00aa00"

    html_body = f"""
    <html>
    <body style="font-family:Arial;background:#020812;padding:20px">
        <div style="max-width:600px;margin:auto;background:#0d1520;
                    border-radius:15px;border:1px solid #1a3a50">
            <div style="background:#1a1a2e;padding:25px;text-align:center;
                        border-bottom:2px solid #e94560">
                <h1 style="color:#e94560;margin:0">🔐 DARKSHIELD</h1>
                <p style="color:#4a7a9b;margin:5px 0 0">BREACH ALERT</p>
            </div>
            <div style="padding:25px">
                <h2 style="color:{color_code}">{severity} RISK DETECTED</h2>
                <table style="width:100%;border-collapse:collapse;margin:15px 0">
                    <tr>
                        <td style="padding:10px;color:#4a7a9b">Email</td>
                        <td style="padding:10px;color:#fff">{to_email}</td>
                    </tr>
                    <tr>
                        <td style="padding:10px;color:#4a7a9b">Breaches</td>
                        <td style="padding:10px;color:#fff">{total}</td>
                    </tr>
                    <tr>
                        <td style="padding:10px;color:#4a7a9b">Risk Score</td>
                        <td style="padding:10px;color:{color_code}">
                            {risk}/100
                        </td>
                    </tr>
                    <tr>
                        <td style="padding:10px;color:#4a7a9b">Leaked Data</td>
                        <td style="padding:10px;color:#fff">
                            {', '.join(fields)}
                        </td>
                    </tr>
                </table>
                <div style="background:#0d1a0d;padding:15px;
                             border-radius:8px;margin-top:15px">
                    <h3 style="color:#4caf50;margin:0 0 10px">
                        🤖 AI Advice
                    </h3>
                    <p style="color:#aaccaa;line-height:1.8;margin:0">
                        {ai_advice}
                    </p>
                </div>
                <div style="background:#0d1a2e;padding:15px;
                             border-radius:8px;margin-top:15px">
                    <h3 style="color:#4a9eff;margin:0 0 10px">
                        🛡️ Immediate Actions
                    </h3>
                    <ol style="color:#7ab0d0;line-height:2;
                                padding-left:20px;margin:0">
                        <li>Change passwords immediately</li>
                        <li>Enable Two-Factor Authentication</li>
                        <li>Monitor accounts for suspicious activity</li>
                        <li>Use unique passwords for each site</li>
                    </ol>
                </div>
            </div>
            <div style="background:#080f18;padding:12px;text-align:center">
                <p style="color:#1a3a50;margin:0;font-size:0.75em">
                    DARKSHIELD — DARK WEB BREACH INTELLIGENCE
                </p>
            </div>
        </div>
    </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"🚨 BREACH ALERT — {severity} | {total} breaches found"
    msg["From"] = SMTP_EMAIL
    msg["To"] = to_email
    msg.attach(MIMEText(html_body, "html"))

    try:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        server.starttls()
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.sendmail(SMTP_EMAIL, to_email, msg.as_string())
        server.quit()
        return {"sent": True, "message": f"✅ Alert sent to {to_email}"}
    except Exception as e:
        return {"sent": False, "error": str(e)}


