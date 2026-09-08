import subprocess
import re
import sys
import os

MORIARTY_PATH = os.path.expanduser("~/Moriarty-Project")

def check_phone_moriarty(phone: str):
    """Get phone info using Moriarty Project"""
    result = {
        "phone":    phone,
        "found":    False,
        "details":  {},
        "source":   "moriarty"
    }

    try:
        # Clean phone number
        clean = phone.strip()
        if not clean.startswith("+"):
            clean = "+91" + clean

        # Run Moriarty script directly
        proc = subprocess.run(
            [
                sys.executable,
                os.path.join(MORIARTY_PATH, "MoriartyProject.py"),
                "--cli",
                clean
            ],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=MORIARTY_PATH
        )

        output = proc.stdout + proc.stderr

        # Parse output
        details = {}

        # Extract carrier
        carrier_match = re.search(r'[Cc]arrier[:\s]+(.+)', output)
        if carrier_match:
            details["carrier"] = carrier_match.group(1).strip()

        # Extract location
        location_match = re.search(r'[Ll]ocation[:\s]+(.+)', output)
        if location_match:
            details["location"] = location_match.group(1).strip()

        # Extract country
        country_match = re.search(r'[Cc]ountry[:\s]+(.+)', output)
        if country_match:
            details["country"] = country_match.group(1).strip()

        # Extract line type
        line_match = re.search(r'[Ll]ine\s*[Tt]ype[:\s]+(.+)', output)
        if line_match:
            details["line_type"] = line_match.group(1).strip()

        if details:
            result["found"]   = True
            result["details"] = details
        else:
            result["raw_output"] = output[:300]

    except subprocess.TimeoutExpired:
        result["error"] = "Moriarty timeout"
    except Exception as e:
        result["error"] = str(e)

    return result
