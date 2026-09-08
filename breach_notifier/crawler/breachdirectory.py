import requests
import os

RAPIDAPI_KEY = os.getenv("RAPIDAPI_KEY")

def check_email_breachdirectory(email: str):
    """Check email using BreachDirectory API"""
    try:
        response = requests.get(
            "https://breachdirectory.p.rapidapi.com/",
            params={
                "func": "auto",
                "term": email
            },
            headers={
                "X-RapidAPI-Key": RAPIDAPI_KEY,
                "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"
            },
            timeout=15
        )

        data = response.json()

        if data.get("found"):
            return {
                "found": True,
                "email": email,
                "source": "breachdirectory",
                "total": data.get("size", 0),
                "breaches": [
                    {
                        "name": r.get("sources", ["Unknown"])[0]
                            if r.get("sources") else "Unknown",
                        "fields": ["email", "password"],
                        "password_hint": r.get("password", "")[:3] + "***"
                            if r.get("password") else "",
                        "sha1": r.get("sha1", ""),
                        "source": "breachdirectory"
                    }
                    for r in data.get("result", [])[:5]
                ]
            }

        return {
            "found": False,
            "email": email,
            "source": "breachdirectory",
            "total": 0,
            "breaches": []
        }

    except Exception as e:
        return {
            "error": str(e),
            "source": "breachdirectory",
            "found": False,
            "breaches": []
        }
