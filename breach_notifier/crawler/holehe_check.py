import subprocess
import json
import re

def check_email_holehe(email: str):
    """Check email registered on 400+ sites using Holehe"""
    result = {
        "email":          email,
        "found_sites":    [],
        "not_found_sites":[],
        "total_found":    0,
        "total_checked":  0,
        "source":         "holehe"
    }

    try:
        # Run holehe command
        proc = subprocess.run(
            ["holehe", email, "--only-used", "--no-color"],
            capture_output=True,
            text=True,
            timeout=120
        )

        output = proc.stdout + proc.stderr
        lines = output.split("\n")

        found = []
        not_found = []

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Found indicator [+]
            if "[+]" in line:
                site = re.sub(r'\[.\]|\s+', ' ', line).strip()
                site = site.replace("[+]", "").strip()
                if site:
                    found.append({
                        "site":   site,
                        "status": "REGISTERED",
                        "icon":   "✅"
                    })

            # Not found indicator [-]
            elif "[-]" in line:
                site = re.sub(r'\[.\]|\s+', ' ', line).strip()
                site = site.replace("[-]", "").strip()
                if site and len(site) > 2:
                    not_found.append(site)

        result["found_sites"]    = found
        result["not_found_sites"] = not_found[:10]
        result["total_found"]    = len(found)
        result["total_checked"]  = len(found) + len(not_found)

    except subprocess.TimeoutExpired:
        result["error"] = "Timeout — holehe took too long"
    except Exception as e:
        result["error"] = str(e)

    return result
