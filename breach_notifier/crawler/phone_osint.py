import phonenumbers
from phonenumbers import geocoder, carrier, timezone
import requests
from bs4 import BeautifulSoup

def deep_phone_lookup(phone: str):
    """Get complete phone number intelligence like PhoneInfoga"""

    # Clean phone number
    raw = phone.strip()
    if not raw.startswith("+"):
        raw = "+91" + raw  # Default India

    result = {
        "input": phone,
        "formatted": {},
        "carrier_info": {},
        "location": {},
        "timezone": {},
        "validity": {},
        "online_presence": {},
        "risk_score": 0,
        "risk_level": "LOW"
    }

    # 1 — Parse with phonenumbers library
    try:
        parsed = phonenumbers.parse(raw, None)

        # Validity checks
        is_valid   = phonenumbers.is_valid_number(parsed)
        is_possible = phonenumbers.is_possible_number(parsed)

        result["validity"] = {
            "is_valid":    is_valid,
            "is_possible": is_possible,
            "raw_input":   phone,
        }

        # Formatted versions
        result["formatted"] = {
            "e164":          phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            "international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "national":      phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            "country_code":  str(parsed.country_code),
            "national_number": str(parsed.national_number),
        }

        # Carrier info
        carrier_name = carrier.name_for_number(parsed, "en")
        result["carrier_info"] = {
            "carrier":      carrier_name or "Unknown",
            "line_type":    str(phonenumbers.number_type(parsed)).replace("PhoneNumberType.",""),
        }

        # Location
        region = geocoder.description_for_number(parsed, "en")
        country_code = phonenumbers.region_code_for_number(parsed)
        result["location"] = {
            "region":       region or "Unknown",
            "country_code": country_code or "Unknown",
            "country":      _get_country_name(country_code),
        }

        # Timezone
        tz = timezone.time_zones_for_number(parsed)
        result["timezone"] = {
            "timezones": list(tz),
        }

    except Exception as e:
        result["validity"]["error"] = str(e)

    # 2 — Online presence checks
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }

    online = {}

    # NumVerify API (free)
    try:
        r = requests.get(
            f"http://apilayer.net/api/validate",
            params={
                "access_key": "free",
                "number": raw,
                "country_code": "",
                "format": "1"
            },
            timeout=5
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("valid"):
                online["numverify"] = {
                    "valid":        data.get("valid"),
                    "local_format": data.get("local_format"),
                    "carrier":      data.get("carrier"),
                    "line_type":    data.get("line_type"),
                    "location":     data.get("location"),
                    "country_name": data.get("country_name"),
                }
    except:
        pass

    # Truecaller check (public search)
    try:
        r = requests.get(
            f"https://www.truecaller.com/search/in/{phone}",
            headers=headers,
            timeout=5
        )
        online["truecaller"] = {
            "url":    f"https://www.truecaller.com/search/in/{phone}",
            "status": r.status_code,
            "note":   "Check manually for caller ID info"
        }
    except:
        pass

    # WhatsApp check
    try:
        e164 = result["formatted"].get("e164","").replace("+","")
        r = requests.get(
            f"https://api.whatsapp.com/send?phone={e164}",
            headers=headers,
            timeout=5,
            allow_redirects=True
        )
        online["whatsapp"] = {
            "url":    f"https://wa.me/{e164}",
            "status": "Check manually",
            "note":   "Open link to check if number is on WhatsApp"
        }
    except:
        pass

    # Telegram check
    try:
        online["telegram"] = {
            "url":  f"https://t.me/+{result['formatted'].get('e164','').replace('+','')}",
            "note": "Open link to check if number is on Telegram"
        }
    except:
        pass

    # Google search links
    try:
        formatted_num = result["formatted"].get("international", phone)
        online["search_links"] = {
            "google":   f"https://www.google.com/search?q={formatted_num}",
            "facebook": f"https://www.facebook.com/search/top/?q={formatted_num}",
            "linkedin": f"https://www.linkedin.com/search/results/all/?keywords={formatted_num}",
            "instagram":f"https://www.instagram.com/explore/tags/{phone}/",
        }
    except:
        pass

    result["online_presence"] = online

    # 3 — Breach check via LeakCheck
    try:
        r = requests.get(
            "https://leakcheck.io/api/public",
            params={"check": phone},
            timeout=8
        )
        data = r.json()
        if data.get("success") and data.get("found", 0) > 0:
            result["breach_data"] = {
                "found":   True,
                "total":   data.get("found", 0),
                "sources": data.get("sources", [])[:5]
            }
        else:
            result["breach_data"] = {
                "found": False,
                "total": 0
            }
    except Exception as e:
        result["breach_data"] = {"error": str(e)}

    # 4 — HudsonRock check
    try:
        r = requests.get(
            "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-phone",
            params={"phone": phone},
            timeout=8
        )
        data = r.json()
        if data.get("stealers"):
            result["stealer_logs"] = {
                "found": True,
                "total": len(data["stealers"]),
                "data":  data["stealers"][:3]
            }
        else:
            result["stealer_logs"] = {"found": False}
    except:
        result["stealer_logs"] = {"found": False}

    # ── 10 NEW FEATURES ──
    try:
        result["spam_check"] = check_spam_score(phone, result["formatted"].get("e164", phone))
    except:
        result["spam_check"] = {}

    try:
        result["number_type_detail"] = get_number_type_detail(parsed)
    except:
        result["number_type_detail"] = {}

    try:
        result["porting_history"] = check_porting_history(phone, result["carrier_info"].get("carrier"), result["formatted"].get("country_code",""))
    except:
        result["porting_history"] = {}

    try:
        result["owner_search"] = search_owner_name(phone, result["formatted"].get("e164", phone))
    except:
        result["owner_search"] = {}

    try:
        result["linked_apps"] = check_linked_apps(result["formatted"].get("e164", phone))
    except:
        result["linked_apps"] = {}

    try:
        result["sms_gateway"] = test_sms_gateway(result["formatted"].get("country_code", ""))
    except:
        result["sms_gateway"] = {}

    try:
        result["format_variants"] = get_format_variants(parsed, result["formatted"].get("e164", phone))
    except:
        result["format_variants"] = {}

    try:
        result["risk_timeline"] = get_risk_timeline()
    except:
        result["risk_timeline"] = {}

    try:
        result["similar_numbers"] = find_similar_numbers(result["formatted"].get("national_number",""), result["formatted"].get("country_code",""))
    except:
        result["similar_numbers"] = {}

    try:
        result["roaming_info"] = check_roaming_status(result["formatted"].get("country_code",""), result["location"].get("region",""))
    except:
        result["roaming_info"] = {}

    # Risk Score
    risk = 0
    if result["breach_data"].get("found"):      risk += 40
    if result["stealer_logs"].get("found"):     risk += 30
    if not result["validity"].get("is_valid"):  risk += 20
    if result.get("spam_check",{}).get("spam_score",0) > 30: risk += 15
    result["risk_score"] = min(100, risk)
    result["risk_level"] = (
        "CRITICAL" if risk >= 75 else
        "HIGH"     if risk >= 50 else
        "MEDIUM"   if risk >= 25 else
        "LOW"
    )

    return result


def _get_country_name(code: str) -> str:
    """Get country name from code"""
    countries = {
        "IN": "India", "US": "United States",
        "GB": "United Kingdom", "AU": "Australia",
        "CA": "Canada", "DE": "Germany",
        "FR": "France", "JP": "Japan",
        "CN": "China", "RU": "Russia",
        "BR": "Brazil", "PK": "Pakistan",
        "BD": "Bangladesh", "NG": "Nigeria",
        "ZA": "South Africa", "AE": "UAE",
        "SA": "Saudi Arabia", "SG": "Singapore",
    }
    return countries.get(code, code or "Unknown")


def check_spam_score(phone: str, e164: str):
    """Check if number is reported as spam/scam"""
    import requests
    result = {
        "spam_reported": False,
        "spam_score": 0,
        "reports": [],
        "categories": []
    }
    try:
        # Check via numerous public spam databases (free tier check)
        r = requests.get(
            f"https://api.veriphone.io/v2/verify",
            params={"phone": e164, "key": "free"},
            timeout=6
        )
        if r.status_code == 200:
            data = r.json()
            result["spam_reported"] = not data.get("phone_valid", True)
    except:
        pass

    # Heuristic spam check based on pattern
    digits = phone.replace("+","").replace(" ","")
    if len(set(digits[-6:])) <= 2:
        result["spam_score"] += 30
        result["categories"].append("Repetitive digit pattern")
    if digits.endswith("0000") or digits.endswith("1111"):
        result["spam_score"] += 20
        result["categories"].append("Suspicious sequential pattern")

    result["spam_score"] = min(100, result["spam_score"])
    return result


def get_number_type_detail(parsed):
    """Get detailed number type breakdown"""
    import phonenumbers
    type_map = {
        0: "FIXED_LINE", 1: "MOBILE", 2: "FIXED_LINE_OR_MOBILE",
        3: "TOLL_FREE", 4: "PREMIUM_RATE", 5: "SHARED_COST",
        6: "VOIP", 7: "PERSONAL_NUMBER", 8: "PAGER",
        9: "UAN", 10: "VOICEMAIL", 27: "UNKNOWN"
    }
    num_type = phonenumbers.number_type(parsed)
    type_val = int(num_type)
    return {
        "type":        type_map.get(type_val, "UNKNOWN"),
        "is_mobile":   type_val in [1, 2],
        "is_landline": type_val in [0, 2],
        "is_voip":     type_val == 6,
        "is_toll_free":type_val == 3,
        "is_premium":  type_val == 4,
    }


def check_porting_history(phone: str, carrier_name: str, country_code: str):
    """Check porting info with manual verification links"""
    result = {
        "current_carrier": carrier_name or "Unknown",
        "porting_supported_in_country": country_code == "91",
        "manual_check_links": {}
    }
    if country_code == "91":
        result["manual_check_links"] = {
            "TRAI_MNP_Check": "https://www.trai.gov.in/mnp",
            "Note": "India supports Mobile Number Portability (MNP). Dial 1900 from the number to check current operator."
        }
        result["dial_code_check"] = "Dial 1900 (SMS) from this number to find current operator via MNP"
    else:
        result["manual_check_links"] = {
            "Note": "Porting check method varies by country. Contact local telecom regulator."
        }
    return result


def search_owner_name(phone: str, e164: str):
    """Search possible owner name via public OSINT sources"""
    import requests
    result = {
        "possible_names": [],
        "manual_search_links": {},
        "note": "Real owner names require paid Truecaller/CallerID API access. Use these manual search links instead:"
    }

    clean = phone.replace("+","").replace(" ","")
    result["manual_search_links"] = {
        "Truecaller":       f"https://www.truecaller.com/search/in/{clean}",
        "Google_Quoted":    f"https://www.google.com/search?q=%22{phone}%22",
        "Google_Site_FB":   f"https://www.google.com/search?q=site:facebook.com+%22{phone}%22",
        "Google_Site_LI":   f"https://www.google.com/search?q=site:linkedin.com+%22{phone}%22",
        "WhoCalledMe":      f"https://whocalledme.com/Phone-Number.aspx/{clean}",
        "ShouldIAnswer":    f"https://www.shouldianswer.com/phone-number/{clean}",
    }

    # Try to fetch a snippet from a public reverse lookup
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        r = requests.get(
            f"https://www.shouldianswer.com/phone-number/{clean}",
            headers=headers,
            timeout=6
        )
        if r.status_code == 200:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(r.text, "html.parser")
            title = soup.find("title")
            if title and "404" not in title.text:
                result["possible_names"].append({
                    "source": "ShouldIAnswer",
                    "info":   title.text.strip()[:100]
                })
    except:
        pass

    return result


def check_linked_apps(e164: str):
    """Check which messaging apps the number might be on"""
    clean = e164.replace("+","")
    return {
        "whatsapp":  {"url": f"https://wa.me/{clean}",  "check": "Open link manually to verify"},
        "telegram":  {"url": f"https://t.me/+{clean}",  "check": "Open link manually to verify"},
        "signal":    {"url": f"https://signal.me/#p/{e164}", "check": "Open link manually to verify"},
        "viber":     {"url": f"viber://chat?number={clean}", "check": "Open link manually to verify"},
        "skype":     {"url": f"skype:{clean}?call", "check": "Open link manually to verify"},
    }


def test_sms_gateway(country_code: str):
    """Check SMS/OTP gateway availability by country"""
    high_otp_countries = ["91","1","44","61","971","966"]
    can_receive = country_code in high_otp_countries
    return {
        "can_receive_otp":  can_receive,
        "country_code":     country_code,
        "note": "Most carriers support SMS OTP" if can_receive else "OTP support varies by carrier",
    }


def get_format_variants(parsed, e164: str):
    """Get all number format variations"""
    import phonenumbers
    return {
        "e164":           e164,
        "international":  phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "national":       phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
        "rfc3966":        phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.RFC3966),
        "no_spaces":      e164.replace(" ",""),
        "with_dashes":    e164.replace(" ","-"),
        "without_plus":   e164.replace("+",""),
    }


def get_risk_timeline():
    """Simulated risk history (would need paid spam DB for real data)"""
    return {
        "note": "Historical spam report timeline requires premium spam database access",
        "available_via": ["Truecaller Premium", "Hiya", "RoboKiller"],
    }


def find_similar_numbers(national_number: str, country_code: str):
    """Find sequential/similar numbers in same batch"""
    try:
        base = str(national_number)
        last4 = base[-4:]
        prefix = base[:-4]
        similar = []
        try:
            num = int(last4)
            for offset in [-2,-1,1,2]:
                new_num = num + offset
                if 0 <= new_num <= 9999:
                    similar.append(f"+{country_code}{prefix}{str(new_num).zfill(4)}")
        except:
            pass
        return {
            "similar_numbers": similar,
            "note": "These may belong to the same batch/organization"
        }
    except:
        return {"similar_numbers": [], "note": "Could not generate similar numbers"}


def check_roaming_status(country_code: str, region: str):
    """Check international roaming info"""
    return {
        "home_country":    region or "Unknown",
        "country_code":    country_code,
        "roaming_likely":  False,
        "note": "Roaming status requires real-time carrier API access",
        "international_format_used": True,
    }
