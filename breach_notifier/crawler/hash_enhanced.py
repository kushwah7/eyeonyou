import requests
import os
import re

VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY","")

def check_virustotal_hash(hash_str: str):
    """Check hash on VirusTotal"""
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{hash_str}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=10
        )
        if r.status_code == 200:
            data = r.json().get("data",{})
            attrs = data.get("attributes",{})
            stats = attrs.get("last_analysis_stats",{})
            results = attrs.get("last_analysis_results",{})

            # Get malicious engines
            malicious_engines = [
                {"engine": k, "result": v.get("result","")}
                for k,v in results.items()
                if v.get("category") == "malicious"
            ][:10]

            return {
                "found":            True,
                "malicious":        stats.get("malicious",0),
                "suspicious":       stats.get("suspicious",0),
                "harmless":         stats.get("harmless",0),
                "undetected":       stats.get("undetected",0),
                "name":             attrs.get("meaningful_name",""),
                "type":             attrs.get("type_description",""),
                "size":             attrs.get("size",0),
                "md5":              attrs.get("md5",""),
                "sha1":             attrs.get("sha1",""),
                "sha256":           attrs.get("sha256",""),
                "first_seen":       attrs.get("first_submission_date",""),
                "last_seen":        attrs.get("last_analysis_date",""),
                "times_submitted":  attrs.get("times_submitted",0),
                "malicious_engines":malicious_engines,
                "is_malware":       stats.get("malicious",0) > 0,
            }
        return {
            "found": False,
            "note": "Hash not found in VirusTotal"
        }
    except Exception as e:
        return {"error": str(e)}


def check_malwarebazaar(hash_str: str):
    """Check hash on MalwareBazaar"""
    try:
        r = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={
                "query": "get_info",
                "hash":  hash_str
            },
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("query_status") == "hash_found":
                info = data.get("data",[{}])[0]
                return {
                    "found":        True,
                    "file_name":    info.get("file_name",""),
                    "file_type":    info.get("file_type",""),
                    "file_size":    info.get("file_size",""),
                    "md5":          info.get("md5_hash",""),
                    "sha256":       info.get("sha256_hash",""),
                    "first_seen":   info.get("first_seen",""),
                    "last_seen":    info.get("last_seen",""),
                    "tags":         info.get("tags",[]),
                    "signature":    info.get("signature",""),
                    "imphash":      info.get("imphash",""),
                    "is_malware":   True,
                    "reporter":     info.get("reporter",""),
                    "origin":       info.get("origin_country",""),
                }
            return {"found": False, "note": "Hash not found in MalwareBazaar"}
    except Exception as e:
        return {"error": str(e)}
    return {"found": False}


def check_onlinehashcrack(hash_str: str, hash_type: str):
    """Try online hash cracking"""
    try:
        # Try multiple sources
        sources = {
            "md5online":    f"https://www.md5online.org/md5-decrypt.html",
            "crackstation": f"https://crackstation.net/",
            "hashkiller":   f"https://hashkiller.io/listmanager",
            "nisteam":      f"https://www.nisteam.fr/",
        }

        # Try gromweb for MD5/SHA1
        if hash_type == "MD5":
            r = requests.get(
                f"https://md5.gromweb.com/?hash={hash_str}",
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=10
            )
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(r.text, "html.parser")
            links = soup.find_all("a", {"class": "String"})
            for link in links:
                text = link.text.strip()
                href = link.get("href","")
                if "string=" in href and text:
                    return {
                        "cracked":   True,
                        "plaintext": text,
                        "method":    "md5.gromweb.com"
                    }

        if hash_type == "SHA1":
            r = requests.get(
                f"https://sha1.gromweb.com/?hash={hash_str}",
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=10
            )
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(r.text, "html.parser")
            links = soup.find_all("a", {"class": "String"})
            for link in links:
                text = link.text.strip()
                href = link.get("href","")
                if "string=" in href and text:
                    return {
                        "cracked":   True,
                        "plaintext": text,
                        "method":    "sha1.gromweb.com"
                    }

        return {
            "cracked": False,
            "search_links": sources,
            "note": "Try manual cracking on these sites"
        }
    except Exception as e:
        return {"error": str(e)}


def get_enhanced_hash_details(hash_str: str, hash_type: str):
    """Get all enhanced hash details"""
    return {
        "hash":          hash_str,
        "hash_type":     hash_type,
        "virustotal":    check_virustotal_hash(hash_str),
        "malwarebazaar": check_malwarebazaar(hash_str),
        "crack_attempt": check_onlinehashcrack(hash_str, hash_type),
    }
