import requests
import os
import shodan

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY","")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY","")
SHODAN_KEY = os.getenv("SHODAN_API_KEY","")

def check_abuseipdb(ip: str):
    """Check IP abuse reports"""
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
                "verbose": True
            },
            timeout=10
        )
        if r.status_code == 200:
            data = r.json().get("data", {})
            return {
                "found":           True,
                "abuse_score":     data.get("abuseConfidenceScore", 0),
                "total_reports":   data.get("totalReports", 0),
                "last_reported":   data.get("lastReportedAt", "Never"),
                "country":         data.get("countryCode", ""),
                "isp":             data.get("isp", ""),
                "domain":          data.get("domain", ""),
                "is_whitelisted":  data.get("isWhitelisted", False),
                "is_tor":          data.get("isTor", False),
                "usage_type":      data.get("usageType", ""),
                "reports":         [
                    {
                        "date":       r.get("reportedAt",""),
                        "categories": r.get("categories",[]),
                        "comment":    r.get("comment","")[:100],
                    }
                    for r in data.get("reports",[])[:5]
                ]
            }
    except Exception as e:
        return {"error": str(e)}
    return {"found": False}


def check_virustotal_ip(ip: str):
    """Check IP on VirusTotal"""
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=10
        )
        if r.status_code == 200:
            data = r.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "found":       True,
                "malicious":   stats.get("malicious", 0),
                "suspicious":  stats.get("suspicious", 0),
                "harmless":    stats.get("harmless", 0),
                "undetected":  stats.get("undetected", 0),
                "reputation":  attrs.get("reputation", 0),
                "country":     attrs.get("country", ""),
                "asn":         attrs.get("asn", ""),
                "as_owner":    attrs.get("as_owner", ""),
                "network":     attrs.get("network", ""),
                "tags":        attrs.get("tags", []),
                "votes": {
                    "harmless":  attrs.get("total_votes",{}).get("harmless",0),
                    "malicious": attrs.get("total_votes",{}).get("malicious",0),
                }
            }
    except Exception as e:
        return {"error": str(e)}
    return {"found": False}


def check_shodan_ip(ip: str):
    """Check IP on Shodan"""
    try:
        api = shodan.Shodan(SHODAN_KEY)
        host = api.host(ip)
        return {
            "found":        True,
            "ip":           host.get("ip_str",""),
            "org":          host.get("org",""),
            "isp":          host.get("isp",""),
            "country":      host.get("country_name",""),
            "city":         host.get("city",""),
            "os":           host.get("os","Unknown"),
            "ports":        host.get("ports",[]),
            "vulns":        list(host.get("vulns",{}).keys())[:10],
            "tags":         host.get("tags",[]),
            "last_update":  host.get("last_update",""),
            "services": [
                {
                    "port":      s.get("port",""),
                    "transport": s.get("transport",""),
                    "product":   s.get("product",""),
                    "version":   s.get("version",""),
                    "banner":    s.get("data","")[:100],
                }
                for s in host.get("data",[])[:5]
            ]
        }
    except shodan.APIError as e:
        return {"error": str(e), "found": False}
    except Exception as e:
        return {"error": str(e), "found": False}


def check_greynoise_ip(ip: str):
    """Check IP on GreyNoise (free)"""
    try:
        r = requests.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers={"key": ""},
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            return {
                "found":       True,
                "noise":       data.get("noise", False),
                "riot":        data.get("riot", False),
                "name":        data.get("name",""),
                "link":        data.get("link",""),
                "last_seen":   data.get("last_seen",""),
                "message":     data.get("message",""),
            }
    except Exception as e:
        return {"error": str(e)}
    return {"found": False}


def get_enhanced_ip_details(ip: str):
    """Get all enhanced IP details"""
    return {
        "ip":         ip,
        "abuseipdb":  check_abuseipdb(ip),
        "virustotal": check_virustotal_ip(ip),
        "shodan":     check_shodan_ip(ip),
        "greynoise":  check_greynoise_ip(ip),
    }
