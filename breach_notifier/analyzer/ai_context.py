from groq import Groq

# Put your actual Groq key here directly
GROQ_KEY = ""

client = Groq(api_key=GROQ_KEY)

def generate_ai_advice(breach_summary: dict) -> str:
    fields = breach_summary.get("all_leaked_fields", [])
    severity = breach_summary.get("severity", "LOW")
    risk = breach_summary.get("overall_risk", 0)
    total = breach_summary.get("total_breaches", 0)

    prompt = f"""
You are a cybersecurity expert.
Breaches found: {total}
Risk Score: {risk}/100
Severity: {severity}
Leaked fields: {', '.join(fields)}
Give 3 simple security tips under 80 words.
"""

    try:
        response = client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content

    except Exception as e:
        return fallback_advice(fields, severity, risk, total)


def fallback_advice(fields, severity, risk, total):
    advice = []
    advice.append(f"⚠️ {total} breach(es) found. Risk: {risk}/100 ({severity})")
    if "password" in fields or "password_hash" in fields:
        advice.append("🔑 Change your passwords immediately.")
    if "email" in fields:
        advice.append("📧 Watch for phishing emails.")
    if "phone" in fields:
        advice.append("📱 Beware of spam calls and SMS.")
    if "credit_card" in fields or "bank_account" in fields:
        advice.append("💳 Contact your bank immediately.")
    advice.append("🔐 Enable Two-Factor Authentication.")
    advice.append("🛡️ Use a password manager.")
    return "\n".join(advice)
