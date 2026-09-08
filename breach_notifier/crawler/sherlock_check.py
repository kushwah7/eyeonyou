import subprocess
import json

def check_username_sherlock(username: str):
    """Check username across 300+ websites using Sherlock"""
    try:
        result = subprocess.run(
            ["sherlock", username, "--json", "--output", "/tmp/sherlock_result.json"],
            capture_output=True,
            text=True,
            timeout=60
        )

        # Read results
        try:
            with open("/tmp/sherlock_result.json", "r") as f:
                data = json.load(f)

            found_sites = [
                {
                    "site": site,
                    "url": info.get("url", ""),
                    "status": info.get("status", ""),
                    "source": "sherlock"
                }
                for site, info in data.items()
                if info.get("status") == "Claimed"
            ]

            return {
                "found": len(found_sites) > 0,
                "username": username,
                "source": "sherlock",
                "total_sites": len(found_sites),
                "sites": found_sites[:10]
            }

        except:
            return {
                "found": False,
                "username": username,
                "source": "sherlock",
                "total_sites": 0,
                "sites": []
            }

    except Exception as e:
        return {
            "error": str(e),
            "source": "sherlock",
            "found": False,
            "sites": []
        }
