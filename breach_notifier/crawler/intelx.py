import requests
import os

INTELX_API_KEY = os.getenv("INTELX_API_KEY")
INTELX_BASE_URL = "https://2.intelx.io"

def search_intelx(query: str):
    """Search IntelX for leaked data"""
    try:
        # Start search
        response = requests.post(
            f"{INTELX_BASE_URL}/intelligent/search",
            headers={
                "x-key": INTELX_API_KEY,
                "Content-Type": "application/json"
            },
            json={
                "term": query,
                "buckets": [],
                "lookuplevel": 0,
                "maxresults": 10,
                "timeout": 30,
                "datefrom": "",
                "dateto": "",
                "sort": 4,
                "media": 0,
                "terminate": []
            },
            timeout=30
        )

        data = response.json()
        search_id = data.get("id")

        if not search_id:
            return {
                "found": False,
                "query": query,
                "source": "intelx",
                "breaches": []
            }

        # Get results
        results_response = requests.get(
            f"{INTELX_BASE_URL}/intelligent/search/result",
            headers={"x-key": INTELX_API_KEY},
            params={
                "id": search_id,
                "limit": 10
            },
            timeout=30
        )

        results = results_response.json()
        records = results.get("records", [])

        if records:
            return {
                "found": True,
                "query": query,
                "source": "intelx",
                "total": len(records),
                "breaches": [
                    {
                        "name": r.get("name", "Unknown"),
                        "date": r.get("date", "Unknown")[:10],
                        "fields": ["email", "password", "username"],
                        "bucket": r.get("bucket", ""),
                        "source": "intelx"
                    }
                    for r in records[:5]
                ]
            }

        return {
            "found": False,
            "query": query,
            "source": "intelx",
            "total": 0,
            "breaches": []
        }

    except Exception as e:
        return {
            "error": str(e),
            "source": "intelx",
            "found": False,
            "breaches": []
        }


def check_email_intelx(email: str):
    return search_intelx(email)

def check_phone_intelx(phone: str):
    return search_intelx(phone)

def check_username_intelx(username: str):
    return search_intelx(username)
