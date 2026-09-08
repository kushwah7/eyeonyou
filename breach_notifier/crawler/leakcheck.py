import requests

BASE_URL = "https://leakcheck.io/api/public"

def check_email_leakcheck(email: str):
    """Check email breach"""
    try:
        response = requests.get(
            BASE_URL,
            params={"check": email},
            timeout=10
        )
        data = response.json()
        if data.get("success") and data.get("found") > 0:
            return {
                "found": True,
                "query": email,
                "type": "email",
                "total_breaches": data.get("found"),
                "breaches": data.get("sources", [])
            }
        return {
            "found": False,
            "query": email,
            "type": "email",
            "total_breaches": 0,
            "breaches": []
        }
    except Exception as e:
        return {"error": str(e)}


def check_username_leakcheck(username: str):
    """Check username breach"""
    try:
        response = requests.get(
            BASE_URL,
            params={"check": username},
            timeout=10
        )
        data = response.json()
        if data.get("success") and data.get("found") > 0:
            return {
                "found": True,
                "query": username,
                "type": "username",
                "total_breaches": data.get("found"),
                "breaches": data.get("sources", [])
            }
        return {
            "found": False,
            "query": username,
            "type": "username",
            "total_breaches": 0,
            "breaches": []
        }
    except Exception as e:
        return {"error": str(e)}


def check_phone_leakcheck(phone: str):
    """Check phone number breach"""
    try:
        response = requests.get(
            BASE_URL,
            params={"check": phone},
            timeout=10
        )
        data = response.json()
        if data.get("success") and data.get("found") > 0:
            return {
                "found": True,
                "query": phone,
                "type": "phone",
                "total_breaches": data.get("found"),
                "breaches": data.get("sources", [])
            }
        return {
            "found": False,
            "query": phone,
            "type": "phone",
            "total_breaches": 0,
            "breaches": []
        }
    except Exception as e:
        return {"error": str(e)}
