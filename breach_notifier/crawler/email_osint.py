import requests
import dns.resolver
import socket
import re
import whois
from datetime import datetime
from bs4 import BeautifulSoup

DISPOSABLE_DOMAINS = [
    "mailinator.com","guerrillamail.com","tempmail.com",
    "10minutemail.com","throwaway.email","yopmail.com",
    "sharklasers.com","guerrillamailblock.com","grr.la",
    "guerrillamail.info","trashmail.com","maildrop.cc",
    "dispostable.com","fakeinbox.com","spam4.me",
    "tempr.email","discard.email","mailnull.com",
]

def check_email_reputation(email: str):
    """Check email reputation using EmailRep-style analysis"""
    try:
        r = requests.get(
            f"https://emailrep.io/{email}",
            headers={"User-Agent": "EyeOnYou-OSINT"},
            timeout=8
        )
        if r.status_code == 200:
            data = r.json()
            return {
                "reputation":     data.get("reputation", "unknown"),
                "suspicious":     data.get("suspicious", False),
                "references":     data.get("references", 0),
                "blacklisted":    data.get("details", {}).get("blacklisted", False),
                "malicious":      data.get("details", {}).get("malicious_activity", False),
                "credentials_leaked": data.get("details", {}).get("credentials_leaked", False),
                "data_breach":    data.get("details", {}).get("data_breach", False),
                "first_seen":     data.get("details", {}).get("first_seen", "unknown"),
                "last_seen":      data.get("details", {}).get("last_seen", "unknown"),
                "spam":           data.get("details", {}).get("spam", False),
                "free_provider":  data.get("details", {}).get("free_provider", False),
                "deliverable":    data.get("details", {}).get("deliverable", True),
                "valid_mx":       data.get("details", {}).get("valid_mx", False),
                "spoofable":      data.get("details", {}).get("spoofable", False),
                "profiles":       data.get("details", {}).get("profiles", []),
            }
    except Exception as e:
        return {"error": str(e)}
    return {}


def validate_email(email: str):
    """Deep email validation"""
    result = {
        "email":        email,
        "format_valid": False,
        "domain":       "",
        "is_disposable": False,
        "is_free":      False,
        "mx_valid":     False,
        "smtp_valid":   False,
        "deliverable":  False,
    }

    # Format check
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return result
    result["format_valid"] = True

    # Extract domain
    domain = email.split("@")[1].lower()
    result["domain"] = domain

    # Disposable check
    result["is_disposable"] = domain in DISPOSABLE_DOMAINS

    # Free provider check
    free_providers = [
        "gmail.com","yahoo.com","hotmail.com","outlook.com",
        "live.com","icloud.com","protonmail.com","yandex.com",
        "rediffmail.com","aol.com","zoho.com",
    ]
    result["is_free"] = domain in free_providers

    # MX record check
    try:
        mx = dns.resolver.resolve(domain, 'MX')
        result["mx_valid"] = len(list(mx)) > 0
        result["mx_records"] = [str(r.exchange) for r in mx][:3]
        result["deliverable"] = True
    except:
        result["mx_valid"] = False
        result["mx_records"] = []

    return result


def get_domain_intelligence(email: str):
    """Get intelligence about email domain"""
    domain = email.split("@")[1]
    result = {
        "domain":       domain,
        "whois":        {},
        "dns":          {},
        "reputation":   {},
        "age_days":     0,
    }

    # WHOIS
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]

        age_days = 0
        if creation:
            age_days = (datetime.now() - creation).days

        result["whois"] = {
            "registrar":     str(w.registrar) if w.registrar else "Unknown",
            "creation_date": str(creation)[:10] if creation else "Unknown",
            "expiry_date":   str(expiry)[:10] if expiry else "Unknown",
            "country":       str(w.country) if hasattr(w,"country") and w.country else "Unknown",
            "org":           str(w.org) if hasattr(w,"org") and w.org else "Unknown",
        }
        result["age_days"] = age_days
        result["domain_age"] = f"{age_days//365} years {(age_days%365)//30} months"

    except Exception as e:
        # Try WhoisXML API for domains that fail
        try:
            import os
            api_key = os.getenv("WHOISXML_API_KEY", "")
            r = requests.get(
                "https://www.whoisxmlapi.com/whoisserver/WhoisService",
                params={
                    "domainName": domain,
                    "outputFormat": "JSON",
                    "apiKey": api_key
                },
                timeout=10
            )
            if r.status_code == 200:
                data = r.json()
                reg = data.get("WhoisRecord", {})
                registrant = reg.get("registrant", {}) or {}
                result["whois"] = {
                    "registrar":     reg.get("registrarName", "Unknown"),
                    "creation_date": (reg.get("createdDate") or "Unknown")[:10],
                    "expiry_date":   (reg.get("expiresDate") or "Unknown")[:10],
                    "country":       registrant.get("country", "Unknown"),
                    "org":           registrant.get("organization", "Unknown"),
                }
                # Calculate age from this data
                if reg.get("createdDate"):
                    try:
                        created = datetime.strptime(reg["createdDate"][:10], "%Y-%m-%d")
                        age = (datetime.now() - created).days
                        result["age_days"] = age
                        result["domain_age"] = f"{age//365} years {(age%365)//30} months"
                    except:
                        pass
        except Exception as e2:
            result["whois"]["error"] = f"{str(e)} | {str(e2)}"

    # DNS
    try:
        dns_data = {}
        for rtype in ["A","MX","TXT","NS"]:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                dns_data[rtype] = [str(r) for r in answers][:3]
            except:
                dns_data[rtype] = []
        result["dns"] = dns_data
    except:
        pass

    return result


def find_social_by_email(email: str):
    """Find social media accounts linked to email"""
    username = email.split("@")[0]
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }

    found = []

    platforms = [
        {"name": "GitHub",   "url": f"https://api.github.com/search/users?q={email}+in:email"},
        {"name": "Gravatar", "url": f"https://www.gravatar.com/{email}"},
    ]

    # GitHub email search
    try:
        r = requests.get(
            f"https://api.github.com/search/users?q={email}+in:email",
            headers=headers, timeout=6
        )
        if r.status_code == 200:
            data = r.json()
            for user in data.get("items", [])[:3]:
                found.append({
                    "platform": "GitHub",
                    "username": user.get("login"),
                    "url":      user.get("html_url"),
                    "avatar":   user.get("avatar_url"),
                })
    except: pass

    # Username based search
    for platform, url_template in [
        ("Reddit",   f"https://www.reddit.com/user/{username}/about.json"),
        ("Dev.to",   f"https://dev.to/api/users/by_username?url={username}"),
    ]:
        try:
            r = requests.get(url_template, headers=headers, timeout=5)
            if r.status_code == 200:
                data = r.json()
                if platform == "Reddit" and data.get("data"):
                    found.append({
                        "platform": "Reddit",
                        "username": data["data"].get("name"),
                        "url":      f"https://reddit.com/user/{username}",
                        "karma":    data["data"].get("total_karma", 0),
                    })
                elif platform == "Dev.to" and data.get("name"):
                    found.append({
                        "platform": "Dev.to",
                        "username": data.get("username"),
                        "url":      f"https://dev.to/{username}",
                        "name":     data.get("name"),
                    })
        except: pass

    return {
        "email":         email,
        "username_used": username,
        "accounts_found": found,
        "total":         len(found),
    }


def check_paste_sites(email: str):
    """Check if email appears on paste sites"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    results = []

    # Check via LeakCheck (already has paste detection)
    try:
        r = requests.get(
            "https://leakcheck.io/api/public",
            params={"check": email},
            timeout=8
        )
        data = r.json()
        if data.get("success") and data.get("found", 0) > 0:
            for source in data.get("sources", [])[:5]:
                results.append({
                    "site":   source.get("name", "Unknown"),
                    "date":   source.get("date", "Unknown"),
                    "fields": source.get("fields", []),
                })
    except: pass

    # Pastebin search link
    paste_links = {
        "pastebin_search": f"https://pastebin.com/search?q={email}",
        "google_paste":    f"https://www.google.com/search?q=site:pastebin.com+{email}",
        "psbdmp":          f"https://psbdmp.ws/api/search/{email}",
    }

    # Check psbdmp (pastebin dump search)
    try:
        r = requests.get(
            f"https://psbdmp.ws/api/search/{email}",
            headers=headers, timeout=8
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("data"):
                for paste in data["data"][:3]:
                    results.append({
                        "site":   "Pastebin",
                        "id":     paste.get("id"),
                        "url":    f"https://pastebin.com/{paste.get('id')}",
                        "date":   paste.get("time"),
                    })
    except: pass

    return {
        "email":       email,
        "found":       len(results) > 0,
        "total":       len(results),
        "pastes":      results,
        "search_links": paste_links,
    }


def check_dark_web_mentions(email: str):
    """Check dark web for email mentions via Tor"""
    try:
        session = requests.Session()
        session.proxies = {
            'http':  'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:91.0)"
        }

        # Search Ahmia
        r = session.get(
            f"https://ahmia.fi/search/?q={email}",
            timeout=30
        )

        soup = BeautifulSoup(r.text, "html.parser")
        results = []
        for result in soup.find_all('li', class_='result')[:5]:
            title = result.find('a')
            desc  = result.find('p')
            if title:
                results.append({
                    "title":       title.get_text(strip=True)[:100],
                    "description": desc.get_text(strip=True)[:200] if desc else "",
                    "source":      "dark_web",
                })

        return {
            "found":   len(results) > 0,
            "total":   len(results),
            "results": results,
        }
    except Exception as e:
        return {
            "found":   False,
            "total":   0,
            "results": [],
            "note":    "Tor not running or dark web unreachable",
        }


def analyze_password_patterns(breaches: list):
    """Analyze what type of passwords were leaked"""
    result = {
        "password_found":  False,
        "hash_types":      [],
        "risk_level":      "LOW",
        "advice":          [],
    }

    for breach in breaches:
        fields = breach.get("fields", []) or breach.get("leaked_fields", [])
        for field in fields:
            field = str(field).lower()
            if "password" in field:
                result["password_found"] = True
                if "hash" in field:
                    result["hash_types"].append("Hashed Password")
                else:
                    result["hash_types"].append("Plain Text Password")

    if result["password_found"]:
        result["risk_level"] = "CRITICAL"
        result["advice"] = [
            "Change password immediately on affected sites",
            "Change same password on ALL other sites",
            "Enable Two-Factor Authentication",
            "Use a password manager",
            "Never reuse passwords across sites",
        ]
    else:
        result["advice"] = [
            "Monitor your accounts regularly",
            "Enable login alerts on all accounts",
        ]

    return result


def find_related_emails(email: str):
    """Find related email variations"""
    username = email.split("@")[0]
    domain   = email.split("@")[1]

    variations = []

    # Common variations
    parts = re.split(r'[._\-]', username)
    if len(parts) >= 2:
        first = parts[0]
        last  = parts[-1]
        free_domains = ["gmail.com","yahoo.com","outlook.com","hotmail.com"]
        for d in free_domains:
            if d != domain:
                variations.extend([
                    f"{first}.{last}@{d}",
                    f"{first}{last}@{d}",
                    f"{first[0]}{last}@{d}",
                    f"{last}.{first}@{d}",
                ])

    return {
        "original":   email,
        "variations": list(set(variations))[:10],
        "username":   username,
        "domain":     domain,
    }


def get_breach_timeline(breaches: list):
    """Build timeline of breaches"""
    timeline = []
    for b in breaches:
        date = b.get("date") or b.get("breach_date", "")
        if date:
            timeline.append({
                "breach": b.get("name", "Unknown"),
                "date":   str(date)[:10],
                "fields": b.get("fields") or b.get("leaked_fields", []),
                "risk":   b.get("risk_score", 0),
            })

    # Sort by date
    timeline.sort(key=lambda x: x["date"], reverse=True)
    return {
        "total":    len(timeline),
        "timeline": timeline,
        "first_breach": timeline[-1]["date"] if timeline else "Never",
        "last_breach":  timeline[0]["date"]  if timeline else "Never",
    }


def full_email_intelligence(email: str, breaches: list = []):
    """Complete email OSINT — all 10 features"""
    return {
        "email":             email,
        "reputation":        check_email_reputation(email),
        "validation":        validate_email(email),
        "domain_intel":      get_domain_intelligence(email),
        "social_accounts":   find_social_by_email(email),
        "paste_sites":       check_paste_sites(email),
        "dark_web":          check_dark_web_mentions(email),
        "password_analysis": analyze_password_patterns(breaches),
        "related_emails":    find_related_emails(email),
        "breach_timeline":   get_breach_timeline(breaches),
    }
