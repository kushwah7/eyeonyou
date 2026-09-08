import re
from collections import Counter

PATTERNS = {
    "sql_injection": [r"(?i)(union\s+select|select\s+\*|drop\s+table|insert\s+into)", r"(?i)('|\"|;|--|#)", r"(?i)(or\s+1=1|and\s+1=1)"],
    "xss": [r"(?i)(<script|javascript:|onerror=|onload=)", r"(?i)(alert\s*\(|document\.cookie)"],
    "path_traversal": [r"(\.\./|\.\.\\)", r"(/etc/passwd|/windows/system32)"],
    "brute_force": [r"(?i)(Failed|Invalid|login|password)"],
    "scanner": [r"(?i)(nikto|nmap|sqlmap|burpsuite)", r"(?i)(python-requests|curl|wget)"],
    "shell_injection": [r"(?i)(;ls|;cat|;id|;whoami)", r"(?i)(\|ls|\|cat|\|id)"],
    "rce": [r"(?i)(exec\(|system\(|shell_exec\()", r"(?i)(cmd=|command=|exec=)"]
}

def detect_attacks(line: str):
    detected = []
    for attack_type, patterns in PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, line):
                detected.append(attack_type)
                break
    return list(set(detected))

def parse_log_file(log_content: str):
    lines = log_content.split("\n")
    total_lines = len(lines)

    result = {
        "summary": {"total_lines": total_lines, "total_requests": 0, "suspicious_lines": 0, "attack_count": 0, "unique_ips": 0, "error_count": 0},
        "attacks": {"sql_injection": [], "xss": [], "path_traversal": [], "brute_force": [], "scanner": [], "shell_injection": [], "rce": []},
        "top_ips": [],
        "suspicious_ips": [],
        "brute_force_ips": [],
        "risk_score": 0,
        "risk_level": "LOW",
        "ai_summary": ""
    }

    ip_counter = Counter()
    failed_logins = Counter()
    suspicious_lines = []
    all_ips = set()

    for line in lines:
        if not line.strip():
            continue
        result["summary"]["total_requests"] += 1

        ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
        if ip_match:
            ip = ip_match.group()
            ip_counter[ip] += 1
            all_ips.add(ip)

        status_match = re.search(r'" (\d{3}) ', line)
        if status_match:
            if status_match.group(1).startswith("4") or status_match.group(1).startswith("5"):
                result["summary"]["error_count"] += 1

        if "Failed" in line or "Invalid" in line:
            if ip_match:
                failed_logins[ip_match.group()] += 1

        attacks = detect_attacks(line)
        if attacks:
            result["summary"]["suspicious_lines"] += 1
            result["summary"]["attack_count"] += 1
            entry = {"line": line[:200], "ip": ip_match.group() if ip_match else "Unknown", "attacks": attacks}
            for attack in attacks:
                if attack in result["attacks"] and len(result["attacks"][attack]) < 5:
                    result["attacks"][attack].append(entry)
            suspicious_lines.append(entry)

    result["top_ips"] = [{"ip": ip, "requests": count} for ip, count in ip_counter.most_common(10)]
    result["summary"]["unique_ips"] = len(all_ips)

    for ip, count in failed_logins.items():
        if count >= 5:
            result["brute_force_ips"].append({"ip": ip, "failed_count": count, "threat": "BRUTE FORCE DETECTED"})

    for entry in suspicious_lines[:5]:
        ip = entry.get("ip", "Unknown")
        if ip != "Unknown":
            result["suspicious_ips"].append({"ip": ip, "attacks": entry["attacks"], "line": entry["line"][:100]})

    risk = 0
    if result["summary"]["attack_count"] > 0: risk += 30
    if result["attacks"]["sql_injection"]: risk += 20
    if result["attacks"]["xss"]: risk += 15
    if result["attacks"]["rce"]: risk += 30
    if result["brute_force_ips"]: risk += 20
    result["risk_score"] = min(100, risk)
    result["risk_level"] = "CRITICAL" if risk >= 75 else "HIGH" if risk >= 50 else "MEDIUM" if risk >= 25 else "LOW"

    result["ai_summary"] = f"Risk Level: {result['risk_level']}. Found {result['summary']['attack_count']} attacks. Immediate investigation recommended!"

    return result
