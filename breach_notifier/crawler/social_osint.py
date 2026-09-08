import requests
from bs4 import BeautifulSoup

def check_social_media(username: str):
    result = {
        "username": username,
        "platforms_found": [],
        "platforms_checked": 0,
        "total_found": 0,
        "risk_score": 0,
        "risk_level": "LOW"
    }

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    found = []

    # 1 — GitHub API
    try:
        r = requests.get(
            f"https://api.github.com/users/{username}",
            headers=headers, timeout=4
        )
        if r.status_code == 200:
            d = r.json()
            found.append({
                "platform": "GitHub",
                "url": d.get("html_url"),
                "found": True,
                "details": {
                    "name":      d.get("name", ""),
                    "bio":       d.get("bio", ""),
                    "location":  d.get("location", ""),
                    "followers": d.get("followers", 0),
                    "following": d.get("following", 0),
                    "repos":     d.get("public_repos", 0),
                    "company":   d.get("company", ""),
                    "blog":      d.get("blog", ""),
                    "email":     d.get("email", ""),
                    "avatar":    d.get("avatar_url", ""),
                    "created":   d.get("created_at", ""),
                }
            })
    except: pass

    # 2 — Reddit API
    try:
        r = requests.get(
            f"https://www.reddit.com/user/{username}/about.json",
            headers=headers, timeout=4
        )
        if r.status_code == 200:
            d = r.json().get("data", {})
            found.append({
                "platform": "Reddit",
                "url": f"https://reddit.com/user/{username}",
                "found": True,
                "details": {
                    "name":          d.get("name", ""),
                    "total_karma":   d.get("total_karma", 0),
                    "post_karma":    d.get("link_karma", 0),
                    "comment_karma": d.get("comment_karma", 0),
                    "verified":      d.get("verified", False),
                    "is_gold":       d.get("is_gold", False),
                    "created":       str(d.get("created_utc", "")),
                }
            })
    except: pass

    # 3 — Instagram check
    try:
        r = requests.get(
            f"https://www.instagram.com/{username}/",
            headers={
                **headers,
                "Accept": "text/html,application/xhtml+xml",
                "Accept-Language": "en-US,en;q=0.9",
            },
            timeout=4
        )
        if r.status_code == 200 and "Page Not Found" not in r.text:
            # Try to extract basic info from page
            soup = BeautifulSoup(r.text, "html.parser")
            meta_desc = soup.find("meta", {"name": "description"})
            og_image = soup.find("meta", {"property": "og:image"})
            title = soup.find("title")

            details = {}
            if meta_desc:
                details["description"] = meta_desc.get("content", "")
            if title:
                details["page_title"] = title.string

            found.append({
                "platform": "Instagram",
                "url": f"https://www.instagram.com/{username}/",
                "found": True,
                "details": details
            })
    except: pass

    # 4 — Twitter/X check
    try:
        r = requests.get(
            f"https://twitter.com/{username}",
            headers=headers, timeout=4
        )
        if r.status_code == 200 and "This account doesn" not in r.text:
            soup = BeautifulSoup(r.text, "html.parser")
            title = soup.find("title")
            found.append({
                "platform": "Twitter/X",
                "url": f"https://twitter.com/{username}",
                "found": True,
                "details": {
                    "page_title": title.string if title else ""
                }
            })
    except: pass

    # 5 — TikTok check
    try:
        r = requests.get(
            f"https://www.tiktok.com/@{username}",
            headers=headers, timeout=4
        )
        if r.status_code == 200 and "Couldn't find this account" not in r.text:
            found.append({
                "platform": "TikTok",
                "url": f"https://www.tiktok.com/@{username}",
                "found": True,
                "details": {}
            })
    except: pass

    # 6 — LinkedIn check
    try:
        r = requests.get(
            f"https://www.linkedin.com/in/{username}",
            headers=headers, timeout=4
        )
        if r.status_code == 200 and "Page not found" not in r.text:
            found.append({
                "platform": "LinkedIn",
                "url": f"https://www.linkedin.com/in/{username}",
                "found": True,
                "details": {}
            })
    except: pass

    # 7 — Pinterest check
    try:
        r = requests.get(
            f"https://www.pinterest.com/{username}/",
            headers=headers, timeout=4
        )
        if r.status_code == 200 and "Sorry! We couldn" not in r.text:
            found.append({
                "platform": "Pinterest",
                "url": f"https://www.pinterest.com/{username}/",
                "found": True,
                "details": {}
            })
    except: pass

    # 8 — YouTube check
    try:
        r = requests.get(
            f"https://www.youtube.com/@{username}",
            headers=headers, timeout=4
        )
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            title = soup.find("title")
            if title and "404" not in title.string:
                found.append({
                    "platform": "YouTube",
                    "url": f"https://www.youtube.com/@{username}",
                    "found": True,
                    "details": {
                        "channel": title.string
                    }
                })
    except: pass

    # 9 — Telegram check
    try:
        r = requests.get(
            f"https://t.me/{username}",
            headers=headers, timeout=4
        )
        if r.status_code == 200 and "If you have Telegram" in r.text:
            soup = BeautifulSoup(r.text, "html.parser")
            name = soup.find("div", {"class": "tgme_page_title"})
            desc = soup.find("div", {"class": "tgme_page_description"})
            photo = soup.find("img", {"class": "tgme_page_photo_image"})
            found.append({
                "platform": "Telegram",
                "url": f"https://t.me/{username}",
                "found": True,
                "details": {
                    "name":        name.text if name else "",
                    "description": desc.text if desc else "",
                    "photo":       photo["src"] if photo else "",
                }
            })
    except: pass

    # 10 — DevTo API
    try:
        r = requests.get(
            f"https://dev.to/api/users/by_username?url={username}",
            headers=headers, timeout=4
        )
        if r.status_code == 200:
            d = r.json()
            found.append({
                "platform": "Dev.to",
                "url": f"https://dev.to/{username}",
                "found": True,
                "details": {
                    "name":     d.get("name", ""),
                    "bio":      d.get("summary", ""),
                    "location": d.get("location", ""),
                    "joined":   d.get("joined_at", ""),
                }
            })
    except: pass

    # 11 — Medium check
    try:
        r = requests.get(
            f"https://medium.com/@{username}",
            headers=headers, timeout=4
        )
        if r.status_code == 200 and "Page not found" not in r.text:
            found.append({
                "platform": "Medium",
                "url": f"https://medium.com/@{username}",
                "found": True,
                "details": {}
            })
    except: pass

    # 12 — Sherlock
    try:
        import subprocess
        proc = subprocess.run(
            ["sherlock", username, "--timeout", "10",
             "--print-found"],
            capture_output=True, text=True, timeout=30
        )
        existing_platforms = [p["platform"] for p in found]
        for line in proc.stdout.split("\n"):
            if "[+]" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    site = parts[0].replace("[+]","").strip()
                    url  = parts[1].strip()
                    if site not in existing_platforms:
                        found.append({
                            "platform": site,
                            "url":      url,
                            "found":    True,
                            "source":   "sherlock",
                            "details":  {}
                        })
    except: pass

    result["platforms_found"]    = found
    result["total_found"]        = len(found)
    result["platforms_checked"]  = 15

    risk = 0
    if len(found) >= 10: risk = 80
    elif len(found) >= 5: risk = 60
    elif len(found) >= 3: risk = 40
    elif len(found) >= 1: risk = 20

    result["risk_score"] = risk
    result["risk_level"] = (
        "CRITICAL" if risk >= 75 else
        "HIGH"     if risk >= 50 else
        "MEDIUM"   if risk >= 25 else
        "LOW"
    )
    return result
