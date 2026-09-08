import subprocess
import os

def check_subdomains_sublist3r(domain: str):
    """Find subdomains using Sublist3r"""
    result = {
        "domain":     domain,
        "subdomains": [],
        "total":      0,
        "source":     "sublist3r"
    }

    try:
        output_file = f"/tmp/sublist3r_{domain}.txt"

        # Run sublist3r
        proc = subprocess.run(
            [
                "sublist3r",
                "-d", domain,
                "-o", output_file,
                "-t", "10",
            ],
            capture_output=True,
            text=True,
            timeout=60
        )

        # Read results
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                subdomains = [
                    line.strip()
                    for line in f.readlines()
                    if line.strip() and domain in line
                ]
            result["subdomains"] = subdomains[:30]
            result["total"]      = len(subdomains)

            # Cleanup
            os.remove(output_file)
        else:
            # Parse stdout
            lines = proc.stdout.split("\n")
            subdomains = []
            for line in lines:
                line = line.strip()
                if domain in line and not line.startswith("["):
                    subdomains.append(line)
            result["subdomains"] = subdomains[:30]
            result["total"]      = len(subdomains)

    except subprocess.TimeoutExpired:
        result["error"] = "Sublist3r timeout"
    except Exception as e:
        result["error"] = str(e)

    return result
