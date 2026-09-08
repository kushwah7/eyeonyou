import subprocess
import json
import re

def check_phone_phoneinfoga(phone: str):
    """Get deep phone info using PhoneInfoga"""
    result = {
        "phone":   phone,
        "found":   False,
        "details": {},
        "source":  "phoneinfoga"
    }

    try:
        # Clean phone
        clean = phone.strip()
        if not clean.startswith("+"):
            clean = "+91" + clean

        # Run phoneinfoga
        proc = subprocess.run(
            ["phoneinfoga", "scan", "-n", clean],
            capture_output=True,
            text=True,
            timeout=30
        )

        output = proc.stdout + proc.stderr

        details = {}

        # Parse output
        # Country code
        country = re.search(r'[Cc]ountry\s*[Cc]ode[:\s]+(\+?\d+)', output)
        if country:
            details["country_code"] = country.group(1).strip()

        # Country name
        country_name = re.search(r'[Cc]ountry[:\s]+([A-Za-z\s]+)', output)
        if country_name:
            details["country"] = country_name.group(1).strip()

        # Carrier
        carrier = re.search(r'[Cc]arrier[:\s]+(.+)', output)
        if carrier:
            details["carrier"] = carrier.group(1).strip()

        # Line type
        line = re.search(r'[Ll]ine\s*[Tt]ype[:\s]+(.+)', output)
        if line:
            details["line_type"] = line.group(1).strip()

        # International format
        intl = re.search(r'[Ii]nternational[:\s]+(.+)', output)
        if intl:
            details["international"] = intl.group(1).strip()

        # Local format
        local = re.search(r'[Ll]ocal[:\s]+(.+)', output)
        if local:
            details["local"] = local.group(1).strip()

        # E164
        e164 = re.search(r'E\.?164[:\s]+(.+)', output)
        if e164:
            details["e164"] = e164.group(1).strip()

        # Location/Region
        region = re.search(r'[Ll]ocation[:\s]+(.+)', output)
        if region:
            details["region"] = region.group(1).strip()

        if details:
            result["found"]   = True
            result["details"] = details
        else:
            result["raw_output"] = output[:500]
            result["note"] = "PhoneInfoga ran but output format different"

    except FileNotFoundError:
        result["error"] = "PhoneInfoga not installed"
    except subprocess.TimeoutExpired:
        result["error"] = "PhoneInfoga timeout"
    except Exception as e:
        result["error"] = str(e)

    return result
