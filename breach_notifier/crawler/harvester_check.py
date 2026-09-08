import subprocess
import re
import os

def check_domain_harvester(domain: str):
    """Find emails and subdomains using theHarvester"""
    result = {
        "domain":     domain,
        "emails":     [],
        "subdomains": [],
        "ips":        [],
        "total_emails":     0,
        "total_subdomains": 0,
        "source":     "theHarvester"
    }

    try:
        proc = subprocess.run(
            [
                "theHarvester",
                "-d", domain,
                "-b", "google,bing,yahoo",
                "-l", "50",
            ],
            capture_output=True,
            text=True,
            timeout=60
        )

        output = proc.stdout + proc.stderr

        # Parse emails
        emails = re.findall(
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            output
        )
        emails = list(set(emails))

        # Parse subdomains
        subdomains = []
        for line in output.split("\n"):
            line = line.strip()
            if domain in line and "@" not in line:
                if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', line):
                    subdomains.append(line)

        # Parse IPs
        ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', output)
        ips = list(set(ips))

        result["emails"]     = emails[:20]
        result["subdomains"] = list(set(subdomains))[:20]
        result["ips"]        = ips[:10]
        result["total_emails"]     = len(emails)
        result["total_subdomains"] = len(subdomains)

    except subprocess.TimeoutExpired:
        result["error"] = "theHarvester timeout"
    except Exception as e:
        result["error"] = str(e)

    return result
