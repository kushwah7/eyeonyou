# crawler/tor_crawler.py
import requests
from bs4 import BeautifulSoup

def get_tor_session():
    """Create a requests session through Tor"""
    session = requests.Session()
    session.proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }
    session.headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0'
    }
    return session


def verify_tor_connection():
    """Check if Tor is working"""
    try:
        session = get_tor_session()
        response = session.get(
            'https://check.torproject.org/api/ip',
            timeout=30
        )
        data = response.json()
        return {
            "tor_active": data.get("IsTor", False),
            "ip": data.get("IP", "unknown")
        }
    except Exception as e:
        return {
            "tor_active": False,
            "error": str(e)
        }


def search_ahmia(query: str):
    """Search dark web using Ahmia search engine"""
    try:
        session = get_tor_session()

        # Search Ahmia for breach related results
        response = session.get(
            f"https://ahmia.fi/search/?q={query}+breach+leaked",
            timeout=30
        )

        soup = BeautifulSoup(response.text, 'html.parser')

        results = []
        # Find all search results
        for result in soup.find_all('li', class_='result')[:5]:
            title = result.find('a')
            desc = result.find('p')

            if title:
                results.append({
                    "title": title.get_text(strip=True),
                    "description": desc.get_text(strip=True) if desc else "No description",
                    "source": "ahmia_darkweb"
                })

        return {
            "found": len(results) > 0,
            "total_results": len(results),
            "results": results
        }

    except Exception as e:
        return {
            "found": False,
            "error": str(e)
        }


def search_darkweb_breach(email: str):
    """Main function to search dark web for email breach"""
    
    print(f"🔍 Searching dark web for: {email}")
    
    # Extract domain from email for broader search
    domain = email.split("@")[1] if "@" in email else email
    username = email.split("@")[0] if "@" in email else email

    # Search for email and username
    email_results = search_ahmia(email)
    username_results = search_ahmia(username)

    return {
        "email": email,
        "darkweb_search": {
            "email_search": email_results,
            "username_search": username_results,
            "total_found": (
                email_results.get("total_results", 0) +
                username_results.get("total_results", 0)
            )
        }
    }
