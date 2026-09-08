import hashlib
import requests
import re
from bs4 import BeautifulSoup

def identify_hash_type(hash_str: str):
    hash_str = hash_str.strip()
    length = len(hash_str)
    if hash_str.startswith("$2a$") or hash_str.startswith("$2b$"):
        return ["bcrypt"]
    if hash_str.startswith("$1$"): return ["MD5 Crypt"]
    if hash_str.startswith("$5$"): return ["SHA256 Crypt"]
    if hash_str.startswith("$6$"): return ["SHA512 Crypt"]
    if re.match(r'^[a-f0-9]+$', hash_str.lower()):
        if length == 32: return ["MD5"]
        if length == 40: return ["SHA1"]
        if length == 56: return ["SHA224"]
        if length == 64: return ["SHA256"]
        if length == 96: return ["SHA384"]
        if length == 128: return ["SHA512"]
    return ["Unknown"]

def crack_hash(hash_str: str, hash_type: str):
    headers = {"User-Agent": "Mozilla/5.0"}
    if hash_type == "MD5":
        try:
            r = requests.get(f"https://md5.gromweb.com/?hash={hash_str}", headers=headers, timeout=8)
            soup = BeautifulSoup(r.text, "html.parser")
            links = soup.find_all("a", {"class": "String"})
            for link in links:
                text = link.text.strip()
                href = link.get("href", "")
                if "string=" in href and text:
                    return {"cracked": True, "plaintext": text, "method": "md5.gromweb.com"}
        except: pass

    if hash_type == "SHA1":
        try:
            r = requests.get(f"https://sha1.gromweb.com/?hash={hash_str}", headers=headers, timeout=8)
            soup = BeautifulSoup(r.text, "html.parser")
            links = soup.find_all("a", {"class": "String"})
            for link in links:
                text = link.text.strip()
                href = link.get("href", "")
                if "string=" in href and text:
                    return {"cracked": True, "plaintext": text, "method": "sha1.gromweb.com"}
        except: pass

    if hash_type == "SHA256":
        try:
            r = requests.get(f"https://sha256.gromweb.com/?hash={hash_str}", headers=headers, timeout=8)
            soup = BeautifulSoup(r.text, "html.parser")
            links = soup.find_all("a", {"class": "String"})
            for link in links:
                text = link.text.strip()
                href = link.get("href", "")
                if "string=" in href and text:
                    return {"cracked": True, "plaintext": text, "method": "sha256.gromweb.com"}
        except: pass

    if hash_type == "SHA1":
        try:
            prefix = hash_str[:5].upper()
            suffix = hash_str[5:].upper()
            r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=8)
            for line in r.text.splitlines():
                h_suffix, count = line.split(":")
                if h_suffix.upper() == suffix:
                    return {"cracked": False, "hibp_found": True, "times_in_breaches": int(count), "message": f"Found in {count} breaches!", "method": "HIBP"}
        except: pass

    return {"cracked": False, "message": "Hash not found in any public database"}

def check_hash_pwned(hash_str: str):
    results = {}
    try:
        sha1 = hash_str.upper()
        if len(sha1) == 40:
            prefix = sha1[:5]
            suffix = sha1[5:]
            r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=8)
            if r.status_code == 200:
                for h in r.text.splitlines():
                    h_suffix, count = h.split(":")
                    if h_suffix.upper() == suffix:
                        results["hibp"] = {"found": True, "times_seen": int(count), "message": f"Found in {count} breaches!"}
                        return results
                results["hibp"] = {"found": False, "message": "Not found in HIBP"}
    except Exception as e:
        results["hibp"] = {"error": str(e)}
    return results

def generate_hash(text: str):
    return {
        "input": text,
        "md5": hashlib.md5(text.encode()).hexdigest(),
        "sha1": hashlib.sha1(text.encode()).hexdigest(),
        "sha224": hashlib.sha224(text.encode()).hexdigest(),
        "sha256": hashlib.sha256(text.encode()).hexdigest(),
        "sha384": hashlib.sha384(text.encode()).hexdigest(),
        "sha512": hashlib.sha512(text.encode()).hexdigest(),
    }

def analyze_hash(hash_str: str):
    hash_str = hash_str.strip()
    result = {
        "hash": hash_str,
        "length": len(hash_str),
        "hash_types": [],
        "breach_check": {},
        "crack_result": {},
        "security_info": {},
        "risk_score": 0,
        "risk_level": "LOW"
    }

    hash_types = identify_hash_type(hash_str)
    result["hash_types"] = hash_types
    primary_type = hash_types[0] if hash_types else "Unknown"

    result["breach_check"] = check_hash_pwned(hash_str)
    if primary_type not in ["Unknown", "bcrypt", "MD5 Crypt", "SHA512 Crypt"]:
        result["crack_result"] = crack_hash(hash_str, primary_type)

    result["security_info"] = {
        "algorithm": primary_type,
        "is_weak": primary_type in ["MD5", "SHA1"],
        "is_salted": hash_str.startswith("$"),
        "recommendation": "⚠ WEAK — MD5/SHA1 are broken! Use SHA256 or bcrypt!" if primary_type in ["MD5", "SHA1"] else "✅ STRONG — Good hash algorithm" if primary_type in ["SHA256", "SHA512", "bcrypt"] else "Unknown strength"
    }

    risk = 0
    if primary_type in ["MD5", "SHA1"]: risk += 50
    if result["breach_check"].get("hibp", {}).get("found"): risk += 30
    if result["crack_result"].get("cracked"): risk += 20
    result["risk_score"] = min(100, risk)
    result["risk_level"] = "CRITICAL" if risk >= 75 else "HIGH" if risk >= 50 else "MEDIUM" if risk >= 25 else "LOW"

    return result
