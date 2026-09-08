import subprocess
import json
import os
import re

def check_username_maigret(username: str):
    """Deep username OSINT using Maigret"""
    result = {
        "username":      username,
        "found_sites":   [],
        "total_found":   0,
        "total_checked": 0,
        "person_info":   {},
        "tags":          [],
        "source":        "maigret"
    }

    try:
        # Run maigret with JSON output
        output_file = f"/tmp/maigret_{username}.json"

        proc = subprocess.run(
            [
                "maigret", username,
                "--json", output_file,
                "--no-color",
                "--timeout", "10",
                "--retries", "1",
            ],
            capture_output=True,
            text=True,
            timeout=180
        )

        # Read JSON output
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                data = json.load(f)

            found = []
            for site_name, site_data in data.items():
                if isinstance(site_data, dict):
                    status = site_data.get("status", {})
                    if isinstance(status, dict):
                        status_id = status.get("id", 0)
                    else:
                        status_id = 0

                    # Status 1 = found
                    if status_id == 1:
                        found.append({
                            "site":     site_name,
                            "url":      site_data.get("url_user", ""),
                            "tags":     site_data.get("tags", []),
                            "status":   "FOUND",
                        })

            result["found_sites"]   = found
            result["total_found"]   = len(found)
            result["total_checked"] = len(data)

            # Extract all unique tags
            all_tags = []
            for site in found:
                all_tags.extend(site.get("tags", []))
            result["tags"] = list(set(all_tags))

            # Cleanup temp file
            os.remove(output_file)

        else:
            # Parse stdout if no JSON file
            output = proc.stdout
            lines = output.split("\n")
            found = []
            for line in lines:
                if "[+]" in line:
                    url_match = re.search(r'https?://\S+', line)
                    if url_match:
                        found.append({
                            "site":   line.split("[+]")[1].strip()[:50],
                            "url":    url_match.group(),
                            "status": "FOUND",
                            "tags":   []
                        })
            result["found_sites"]   = found
            result["total_found"]   = len(found)

    except subprocess.TimeoutExpired:
        result["error"] = "Timeout — maigret took too long"
    except Exception as e:
        result["error"] = str(e)

    return result
