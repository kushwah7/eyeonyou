import subprocess
import re
import sys
import os

EMAIL2PHONE_PATH = os.path.expanduser("~/email2phonenumber")

def find_phone_from_email(email: str):
    """Find phone number linked to email using Email2PhoneNumber"""
    result = {
        "email":           email,
        "found":           False,
        "phone_numbers":   [],
        "generated":       [],
        "source":          "email2phonenumber",
        "search_links":    {}
    }

    # 1 — Scrape method
    try:
        proc = subprocess.run(
            [
                sys.executable,
                os.path.join(EMAIL2PHONE_PATH, "email2phonenumber.py"),
                "scrape",
                "-e", email
            ],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=EMAIL2PHONE_PATH
        )

        output = proc.stdout + proc.stderr

        # Extract phone numbers
        phones = re.findall(
            r'(\+?[0-9][0-9\s\-\(\)]{7,14}[0-9])',
            output
        )
        phones = [
            re.sub(r'[\s\-\(\)]','',p).strip()
            for p in phones
            if len(re.sub(r'[\s\-\(\)]','',p).strip()) >= 8
            and re.sub(r'[\s\-\(\)]','',p).strip().replace('+','').isdigit()
        ]

        if phones:
            result["found"]         = True
            result["phone_numbers"] = list(set(phones))[:5]

        result["scrape_output"] = output[:300]

    except Exception as e:
        result["scrape_error"] = str(e)

    # 2 — Generate method (safe — just generates patterns)
    try:
        proc2 = subprocess.run(
            [
                sys.executable,
                os.path.join(EMAIL2PHONE_PATH, "email2phonenumber.py"),
                "generate",
                "-e", email
            ],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=EMAIL2PHONE_PATH
        )

        output2 = proc2.stdout

        # Extract generated numbers
        generated = re.findall(
            r'(\+?[0-9][0-9\s\-\(\)]{7,14}[0-9])',
            output2
        )
        generated = [
            re.sub(r'[\s\-\(\)]','',g).strip()
            for g in generated
            if len(re.sub(r'[\s\-\(\)]','',g).strip()) >= 8
            and re.sub(r'[\s\-\(\)]','',g).strip().replace('+','').isdigit()
        ]
        result["generated"] = list(set(generated))[:10]

    except Exception as e:
        result["generate_error"] = str(e)

    # 3 — Manual search links
    username = email.split("@")[0]
    result["search_links"] = {
        "Truecaller":    f"https://www.truecaller.com/search/in/{username}",
        "Google":        f"https://www.google.com/search?q=%22{email}%22+phone+OR+mobile+OR+contact",
        "Facebook":      f"https://www.facebook.com/search/top/?q={email}",
        "LinkedIn":      f"https://www.linkedin.com/search/results/all/?keywords={email}",
        "Instagram":     f"https://www.instagram.com/{username}/",
        "WhatsApp":      f"https://api.whatsapp.com/send?phone={username}",
    }

    return result
