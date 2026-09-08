import requests

def check_email_hudsonrock(email: str):
    """Check email using HudsonRock free API"""
    try:
        response = requests.get(
            f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email",
            params={"email": email},
            timeout=10
        )
        data = response.json()
        if data.get("stealers"):
            return {
                "found": True,
                "email": email,
                "source": "hudsonrock",
                "total": len(data["stealers"]),
                "breaches": [
                    {
                        "name": s.get("malware_path", "Unknown"),
                        "date": s.get("date_uploaded", "Unknown"),
                        "fields": ["email", "password", "username"],
                        "source": "hudsonrock"
                    }
                    for s in data["stealers"][:5]
                ]
            }
        return {
            "found": False,
            "email": email,
            "source": "hudsonrock",
            "total": 0,
            "breaches": []
        }
    except Exception as e:
        return {"error": str(e), "source": "hudsonrock"}


def check_phone_hudsonrock(phone: str):
    """Check phone using HudsonRock free API"""
    try:
        response = requests.get(
            f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-phone",
            params={"phone": phone},
            timeout=10
        )
        data = response.json()
        if data.get("stealers"):
            return {
                "found": True,
                "phone": phone,
                "source": "hudsonrock",
                "total": len(data["stealers"]),
                "breaches": [
                    {
                        "name": s.get("malware_path", "Unknown"),
                        "date": s.get("date_uploaded", "Unknown"),
                        "fields": ["phone", "email", "password"],
                        "source": "hudsonrock"
                    }
                    for s in data["stealers"][:5]
                ]
            }
        return {
            "found": False,
            "phone": phone,
            "source": "hudsonrock",
            "total": 0,
            "breaches": []
        }
    except Exception as e:
        return {"error": str(e), "source": "hudsonrock"}
