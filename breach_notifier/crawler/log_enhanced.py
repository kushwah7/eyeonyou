import os
import requests
import re
from collections import Counter
from datetime import datetime

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY","")

import os

# MITRE ATT&CK technique mapping
MITRE_MAPPING = {
    "sql_injection":   {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "xss":             {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "path_traversal":  {"id": "T1083",  "name": "File and Directory Discovery", "tactic": "Discovery"},
    "brute_force":     {"id": "T1110",  "name": "Brute Force", "tactic": "Credential Access"},
    "scanner":         {"id": "T1595",  "name": "Active Scanning", "tactic": "Reconnaissance"},
    "shell_injection": {"id": "T1059",  "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "rce":             {"id": "T1203",  "name": "Exploitation for Client Execution", "tactic": "Execution"},
}


def check_ip_abuseipdb_bulk(ips: list):
    """Check multiple IPs on AbuseIPDB"""
    results = {}
    for ip in ips[:5]:
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Key": ABUSEIPDB_KEY,
                    "Accept": "application/json"
                },
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": 90,
                },
                timeout=8
            )
            if r.status_code == 200:
                data = r.json().get("data",{})
                results[ip] = {
                    "abuse_score":   data.get("abuseConfidenceScore",0),
                    "total_reports": data.get("totalReports",0),
                    "country":       data.get("countryCode",""),
                    "isp":           data.get("isp",""),
                    "is_tor":        data.get("isTor",False),
                }
        except:
            pass
    return results


def map_mitre_attacks(attacks: dict):
    """Map detected attacks to MITRE ATT&CK framework"""
    mapped = []
    for attack_type, entries in attacks.items():
        if entries and attack_type in MITRE_MAPPING:
            technique = MITRE_MAPPING[attack_type]
            mapped.append({
                "attack_type":   attack_type,
                "technique_id":  technique["id"],
                "technique_name":technique["name"],
                "tactic":        technique["tactic"],
                "count":         len(entries),
                "mitre_url":     f"https://attack.mitre.org/techniques/{technique['id']}/",
            })
    return mapped


def generate_attack_timeline(lines: list):
    """Generate timeline of attacks"""
    timeline = []
    time_pattern = re.compile(
        r'(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}|\w+\s+\d+\s+\d{2}:\d{2}:\d{2})'
    )

    for line in lines[:100]:
        time_match = time_pattern.search(line)
        if time_match:
            ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
            timeline.append({
                "time":   time_match.group(1),
                "ip":     ip_match.group() if ip_match else "Unknown",
                "line":   line[:100],
            })
    return timeline[:20]


def get_enhanced_log_details(log_content: str, attacks: dict, top_ips: list):
    """Get enhanced log analysis"""
    lines = log_content.split("\n")

    # Get top attacker IPs
    ip_list = [ip["ip"] for ip in top_ips[:5]]

    # Check IPs on AbuseIPDB
    abuse_results = check_ip_abuseipdb_bulk(ip_list)

    # Map to MITRE ATT&CK
    mitre_mapping = map_mitre_attacks(attacks)

    # Generate timeline
    timeline = generate_attack_timeline(lines)

    # Attack statistics
    attack_stats = {
        attack: len(entries)
        for attack, entries in attacks.items()
        if entries
    }

    return {
        "abuseipdb_results": abuse_results,
        "mitre_mapping":     mitre_mapping,
        "attack_timeline":   timeline,
        "attack_statistics": attack_stats,
        "total_attack_types": len([a for a in attacks.values() if a]),
    }
