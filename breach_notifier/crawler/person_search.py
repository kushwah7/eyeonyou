import requests
from bs4 import BeautifulSoup

def search_person(name: str, city: str = ""):
    """Search person details from multiple free sources"""

    query = f"{name} {city}".strip()
    result = {
        "name": name,
        "city": city,
        "query": query,
        "social_profiles": [],
        "email_patterns": [],
        "phone_patterns": [],
        "news_mentions": [],
        "linkedin": {},
        "github": {},
        "professional": {},
        "risk_score": 0,
        "risk_level": "LOW"
    }

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0"
    }

    # 1 — GitHub Search
    try:
        r = requests.get(
            "https://api.github.com/search/users",
            params={"q": name, "per_page": 5},
            headers=headers,
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            github_users = []
            for user in data.get("items", []):
                # Get full profile
                profile = requests.get(
                    user["url"],
                    headers=headers,
                    timeout=5
                ).json()
                github_users.append({
                    "username":  user.get("login"),
                    "url":       user.get("html_url"),
                    "name":      profile.get("name", ""),
                    "bio":       profile.get("bio", ""),
                    "location":  profile.get("location", ""),
                    "email":     profile.get("email", ""),
                    "company":   profile.get("company", ""),
                    "followers": profile.get("followers", 0),
                    "repos":     profile.get("public_repos", 0),
                    "avatar":    profile.get("avatar_url", ""),
                })
            result["github"]["profiles"] = github_users
            result["github"]["total"] = len(github_users)
    except Exception as e:
        result["github"]["error"] = str(e)

    # 2 — Email pattern generator
    try:
        name_parts = name.lower().split()
        if len(name_parts) >= 2:
            first = name_parts[0]
            last = name_parts[-1]
            domains = [
                "gmail.com", "yahoo.com",
                "outlook.com", "hotmail.com"
            ]
            patterns = []
            for domain in domains:
                patterns.extend([
                    f"{first}.{last}@{domain}",
                    f"{first}{last}@{domain}",
                    f"{first[0]}{last}@{domain}",
                    f"{first}_{last}@{domain}",
                    f"{last}.{first}@{domain}",
                ])
            result["email_patterns"] = patterns
    except Exception as e:
        result["email_patterns"] = []

    # 3 — Username patterns
    try:
        name_parts = name.lower().split()
        if len(name_parts) >= 2:
            first = name_parts[0]
            last = name_parts[-1]
            result["username_patterns"] = [
                f"{first}{last}",
                f"{first}.{last}",
                f"{first}_{last}",
                f"{first[0]}{last}",
                f"{last}{first}",
                f"{first}{last}123",
                f"{first}{last}__",
            ]
    except:
        result["username_patterns"] = []

    # 4 — News mentions via DuckDuckGo
    try:
        r = requests.get(
            "https://api.duckduckgo.com/",
            params={
                "q": query,
                "format": "json",
                "no_html": 1,
                "skip_disambig": 1
            },
            headers=headers,
            timeout=10
        )
        data = r.json()

        # Abstract
        if data.get("Abstract"):
            result["news_mentions"].append({
                "title":   data.get("Heading", ""),
                "summary": data.get("Abstract", ""),
                "url":     data.get("AbstractURL", ""),
                "source":  data.get("AbstractSource", "")
            })

        # Related topics
        topics = []
        for topic in data.get("RelatedTopics", [])[:5]:
            if isinstance(topic, dict) and topic.get("Text"):
                topics.append({
                    "text": topic.get("Text", ""),
                    "url":  topic.get("FirstURL", "")
                })
        result["related_topics"] = topics

    except Exception as e:
        result["news_mentions"] = []

    # 5 — Professional info via LinkedIn
    try:
        r = requests.get(
            f"https://www.linkedin.com/pub/dir/?first={name.split()[0]}&last={name.split()[-1] if len(name.split()) > 1 else ''}&search=Search",
            headers=headers,
            timeout=10
        )
        result["linkedin"] = {
            "search_url": f"https://www.linkedin.com/search/results/people/?keywords={query.replace(' ', '%20')}",
            "status": r.status_code
        }
    except Exception as e:
        result["linkedin"]["error"] = str(e)

    # 6 — Check breach databases for name
    try:
        r = requests.get(
            "https://leakcheck.io/api/public",
            params={"check": name},
            timeout=10
        )
        data = r.json()
        if data.get("success") and data.get("found", 0) > 0:
            result["breach_data"] = {
                "found": True,
                "total": data.get("found", 0),
                "sources": data.get("sources", [])[:5]
            }
        else:
            result["breach_data"] = {"found": False, "total": 0}
    except Exception as e:
        result["breach_data"] = {"error": str(e)}

    # Risk Score
    risk = 0
    if result["github"].get("total", 0) > 0: risk += 20
    if result["news_mentions"]: risk += 20
    if result.get("breach_data", {}).get("found"): risk += 40
    if result["email_patterns"]: risk += 10
    result["risk_score"] = min(100, risk)
    result["risk_level"] = (
        "CRITICAL" if risk >= 75 else
        "HIGH"     if risk >= 50 else
        "MEDIUM"   if risk >= 25 else
        "LOW"
    )

    return result
