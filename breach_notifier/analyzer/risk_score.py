from datetime import datetime

FIELD_WEIGHTS = {
    "password":       30,
    "password_hash":  20,
    "ssn":            45,
    "credit_card":    45,
    "phone":          15,
    "address":        15,
    "dob":            20,
    "bank_account":   40,
    "username":       10,
    "name":           10,
    "gender":         5,
    "job_title":      5,
    "email":          5,
    "ip_address":     8,
}

BREACH_FIELDS_MAP = {
    "facebook":   ["email", "phone", "name", "dob", "address"],
    "linkedin":   ["email", "name", "job_title", "username"],
    "adobe":      ["email", "password_hash", "username"],
    "twitter":    ["email", "username", "phone"],
    "zomato":     ["email", "password_hash", "name", "phone"],
    "byju":       ["email", "name", "phone"],
    "bigbasket":  ["email", "name", "phone", "address"],
    "dominos":    ["email", "name", "phone", "address"],
    "mobikwik":   ["email", "phone", "address", "dob"],
    "1win":       ["email", "username", "password_hash"],
    "cutout":     ["email", "username"],
    "stockx":     ["email", "name", "username", "password_hash"],
    "instagram":  ["email", "phone", "name", "username"],
    "snapchat":   ["email", "phone", "username"],
    "telegram":   ["phone", "name", "username"],
    "truecaller": ["phone", "name", "address"],
    "justdial":   ["phone", "name", "email", "address"],
}

def get_smart_fields(breach_name: str, search_type: str = "email") -> list:
    """Detect leaked fields based on breach name and search type"""
    name_lower = str(breach_name).lower()

    # Check known breaches first
    for key in BREACH_FIELDS_MAP:
        if key in name_lower:
            return BREACH_FIELDS_MAP[key]

    # Default based on search type
    if search_type == "phone":
        return ["phone", "name", "email", "address", "dob"]
    elif search_type == "username":
        return ["username", "email", "password_hash"]
    else:
        return ["email", "username", "password_hash"]


def analyze_all_breaches(breaches: list, search_type: str = "email") -> dict:
    """Analyze all breaches and return complete summary"""

    if not breaches:
        return {
            "total_breaches": 0,
            "overall_risk": 0,
            "severity": "SAFE",
            "color": "🟢",
            "all_leaked_fields": [],
            "analyzed_breaches": []
        }

    analyzed = []

    for breach in breaches:
        # Get fields
        leaked_fields = breach.get("fields", [])

        # If no fields use smart detection
        if not leaked_fields:
            leaked_fields = get_smart_fields(
                breach.get("name", ""),
                search_type
            )

        # Calculate base score
        base_score = sum(
            FIELD_WEIGHTS.get(str(f).lower(), 5)
            for f in leaked_fields
        )

        # Recency factor
        breach_date = breach.get("date", "")
        recency_factor = 1.0
        if breach_date:
            try:
                date = datetime.strptime(
                    str(breach_date)[:7], "%Y-%m"
                )
                days_old = (datetime.now() - date).days
                recency_factor = max(0.5, 1 - (days_old / 1825))
            except:
                recency_factor = 0.8

        # Dark web multiplier
        source = breach.get("source", "")
        source_multiplier = 1.5 if source == "darkweb" else 1.0

        # Final score
        final_score = min(100, int(
            base_score * recency_factor * source_multiplier
        ))

        # Severity
        if final_score >= 75:
            severity = "CRITICAL"
            color = "🔴"
        elif final_score >= 50:
            severity = "HIGH"
            color = "🟠"
        elif final_score >= 25:
            severity = "MEDIUM"
            color = "🟡"
        else:
            severity = "LOW"
            color = "🟢"

        analyzed.append({
            **breach,
            "risk_score": final_score,
            "severity": severity,
            "color": color,
            "leaked_fields": leaked_fields
        })

    # Overall risk
    overall_risk = max(b["risk_score"] for b in analyzed)

    if overall_risk >= 75:
        severity = "CRITICAL"
        color = "🔴"
    elif overall_risk >= 50:
        severity = "HIGH"
        color = "🟠"
    elif overall_risk >= 25:
        severity = "MEDIUM"
        color = "🟡"
    else:
        severity = "LOW"
        color = "🟢"

    # All unique leaked fields
    all_fields = list(set(
        str(f)
        for b in analyzed
        for f in b.get("leaked_fields", [])
    ))

    return {
        "total_breaches": len(analyzed),
        "overall_risk": overall_risk,
        "severity": severity,
        "color": color,
        "all_leaked_fields": all_fields,
        "analyzed_breaches": analyzed
    }
