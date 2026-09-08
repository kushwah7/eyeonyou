import requests

def get_ip_details(ip: str):
    result = {"ip": ip, "basic": {}, "security": {}, "network": {}}

    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,continent,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"},
            timeout=8
        )
        data = r.json()
        if data.get("status") == "success":
            result["basic"] = {
                "ip": data.get("query"),
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "zip": data.get("zip"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "timezone": data.get("timezone"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "as": data.get("as"),
                "as_name": data.get("asname"),
                "reverse_dns": data.get("reverse"),
                "is_mobile": data.get("mobile"),
                "is_proxy": data.get("proxy"),
                "is_hosting": data.get("hosting"),
                "map_url": f"https://www.openstreetmap.org/?mlat={data.get('lat')}&mlon={data.get('lon')}#map=12/{data.get('lat')}/{data.get('lon')}"
            }
            result["security"] = {
                "is_vpn": data.get("proxy", False),
                "is_datacenter": data.get("hosting", False),
                "is_mobile": data.get("mobile", False),
                "is_tor": False,
                "threat_level": "HIGH" if data.get("proxy") else "LOW"
            }
    except Exception as e:
        result["basic"]["error"] = str(e)

    # Network info
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=8)
        data = r.json()
        result["network"] = {
            "hostname": data.get("hostname"),
            "org": data.get("org"),
            "asn": data.get("org", "").split()[0] if data.get("org") else "",
            "abuse_email": data.get("abuse", {}).get("email") if isinstance(data.get("abuse"), dict) else "",
        }
    except Exception as e:
        result["network"]["error"] = str(e)

    # Risk
    risk = 0
    if result["security"].get("is_vpn"): risk += 30
    if result["security"].get("is_datacenter"): risk += 20
    result["risk_score"] = min(100, risk)
    result["risk_level"] = "CRITICAL" if risk >= 75 else "HIGH" if risk >= 50 else "MEDIUM" if risk >= 25 else "LOW"

    return result
