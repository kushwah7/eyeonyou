import requests
import whois
import dns.resolver
import socket
import ssl
from bs4 import BeautifulSoup
import re
import random

TOR_PROXY = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

def get_session(use_tor=True):
    session = requests.Session()
    if use_tor:
        session.proxies = TOR_PROXY
    session.headers.update({
        "User-Agent": random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        ]),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    })
    return session

def get_my_ip(session):
    try:
        r = session.get("http://ip-api.com/json/", timeout=10)
        data = r.json()
        return {"ip": data.get("query"), "country": data.get("country"), "isp": data.get("isp")}
    except Exception as e:
        return {"error": str(e)}

def fetch_url(session, url, timeout=10, verify=False):
    return session.get(url, timeout=timeout, verify=verify, allow_redirects=True)

def check_http_methods(session, full_url):
    vulns = []
    methods = ["TRACE", "PUT", "DELETE", "OPTIONS"]
    for method in methods:
        try:
            r = session.request(method, full_url, timeout=5)
            if r.status_code == 200:
                vulns.append({
                    "severity": "MEDIUM" if method == "TRACE" else "LOW",
                    "title": f"Dangerous HTTP Method Enabled: {method}",
                    "description": f"{method} method returned 200. Can be used for XST attacks or unauthorized uploads.",
                    "remediation": f"Disable {method} method in web server configuration"
                })
        except:
            pass
    return vulns

def check_mixed_content(full_url, html):
    vulns = []
    if full_url.startswith("https://"):
        http_resources = re.findall(r'http://[^"\s\')<>]+', html)
        if http_resources:
            vulns.append({
                "severity": "MEDIUM",
                "title": "Mixed Content Detected",
                "description": f"Found {len(http_resources)} HTTP resources loaded on HTTPS page. Can be intercepted/modified by attackers.",
                "remediation": "Upgrade all resources to HTTPS or use protocol-relative URLs"
            })
    return vulns

def check_leaked_secrets(html):
    vulns = []
    patterns = {
        r'(?i)(api[_-]?key\s*[:=]\s*["\']?[a-z0-9]{16,}["\']?)': "API Key exposed in source",
        r'(?i)(secret\s*[:=]\s*["\']?[a-z0-9]{16,}["\']?)': "Secret token exposed in source",
        r'(?i)(aws_access_key_id\s*[:=]\s*["\']?AKIA[0-9A-Z]{16}["\']?)': "AWS Access Key exposed",
        r'(?i)(password\s*[:=]\s*["\'][^"\']{4,}["\'])': "Hardcoded password detected",
        r'(?i)(private[_-]?key)': "Private key reference found",
        r'(?i)(authorization:\s*bearer\s+[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_-]+)': "JWT token exposed",
        r'(?i)(sk-[a-z0-9]{48})': "OpenAI API Key exposed",
        r'(?i)(ghp_[a-zA-Z0-9]{36})': "GitHub Personal Access Token exposed",
    }
    for pattern, desc in patterns.items():
        if re.search(pattern, html):
            vulns.append({
                "severity": "CRITICAL",
                "title": "Sensitive Credential Leaked",
                "description": desc + " in HTML/JavaScript source code.",
                "remediation": "Remove hardcoded credentials. Use environment variables or secret managers."
            })
            break
    return vulns

def check_internal_ips(html):
    vulns = []
    private_ips = re.findall(r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b', html)
    if private_ips:
        vulns.append({
            "severity": "MEDIUM",
            "title": "Internal IP Address Disclosure",
            "description": f"Private IP(s) found in response: {', '.join(list(set(private_ips))[:3])}. Reveals internal network structure.",
            "remediation": "Remove internal IP references from public-facing responses"
        })
    return vulns

def check_html_comments(html):
    vulns = []
    comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
    sensitive_keywords = ['password', 'passwd', 'secret', 'key', 'token', 'admin', 'todo', 'fixme', 'hack', 'internal', 'debug']
    for comment in comments:
        c_lower = comment.lower()
        for kw in sensitive_keywords:
            if kw in c_lower and len(comment.strip()) > 5:
                vulns.append({
                    "severity": "LOW",
                    "title": "Sensitive Information in HTML Comment",
                    "description": f"HTML comment contains keyword '{kw}'. May expose internal details.",
                    "remediation": "Remove sensitive comments from production HTML"
                })
                break
        if vulns:
            break
    return vulns

def check_security_txt(session, full_url):
    vulns = []
    try:
        r = fetch_url(session, f"{full_url}/.well-known/security.txt", timeout=5)
        if r.status_code != 200:
            vulns.append({
                "severity": "INFO",
                "title": "Missing security.txt",
                "description": "security.txt file not found. Makes it harder for researchers to report vulnerabilities.",
                "remediation": "Add security.txt at /.well-known/security.txt with contact info"
            })
    except:
        pass
    return vulns

def check_open_redirect(session, full_url):
    vulns = []
    redirect_params = ["?next=", "?redirect=", "?url=", "?return=", "?redirect_uri=", "?continue="]
    test_payload = "https://evil.com"
    for param in redirect_params:
        try:
            r = fetch_url(session, f"{full_url}{param}{test_payload}", timeout=5)
            if "evil.com" in r.url or r.status_code in [301, 302, 307, 308]:
                vulns.append({
                    "severity": "HIGH",
                    "title": "Open Redirect Vulnerability",
                    "description": f"Parameter {param} allows arbitrary URL redirects. Can be used for phishing.",
                    "remediation": "Whitelist allowed redirect destinations or use internal mapping"
                })
                break
        except:
            pass
    return vulns

def check_sql_errors(html):
    vulns = []
    sql_errors = [
        "sql syntax", "mysql_fetch", "pg_query", "ora-", "sqlite3",
        "sqlstate", "odbc driver", "jdbc", "microsoft ole db"
    ]
    html_lower = html.lower()
    for err in sql_errors:
        if err in html_lower:
            vulns.append({
                "severity": "HIGH",
                "title": "Database Error Information Disclosure",
                "description": "SQL/database error messages exposed in response. Reveals backend technology and query structure.",
                "remediation": "Implement custom error pages. Never expose raw database errors."
            })
            break
    return vulns

def check_stack_traces(html):
    vulns = []
    trace_indicators = ["traceback", "stack trace", "at java.", "at com.", "in /var/www", "line ", "file \""]
    html_lower = html.lower()
    for ind in trace_indicators:
        if ind in html_lower and ("error" in html_lower or "exception" in html_lower):
            vulns.append({
                "severity": "MEDIUM",
                "title": "Stack Trace Information Disclosure",
                "description": "Application stack traces exposed in error responses. Reveals code structure and file paths.",
                "remediation": "Configure custom error handlers. Disable debug mode in production."
            })
            break
    return vulns

def check_jquery_version(html):
    vulns = []
    match = re.search(r'jquery[/-]?(\d+\.\d+\.\d+)', html.lower())
    if match:
        version = match.group(1)
        major, minor, patch = map(int, version.split('.'))
        if major < 3 or (major == 3 and minor < 5):
            vulns.append({
                "severity": "MEDIUM",
                "title": f"Outdated jQuery Version ({version})",
                "description": f"jQuery {version} has known XSS and prototype pollution vulnerabilities. Current secure: 3.7.x",
                "remediation": "Upgrade jQuery to latest stable version"
            })
    return vulns

def check_wp_version(session, full_url, html):
    vulns = []
    if "wordpress" in html.lower():
        match = re.search(r'<meta name="generator" content="WordPress (\d+\.\d+(\.\d+)?)"', html, re.I)
        if match:
            version = match.group(1)
            major, minor = map(int, version.split('.')[:2])
            if major < 6 or (major == 6 and minor < 4):
                vulns.append({
                    "severity": "HIGH",
                    "title": f"Outdated WordPress ({version})",
                    "description": f"WordPress {version} may have known CVEs. Latest stable is recommended.",
                    "remediation": "Update WordPress core, themes, and plugins immediately"
                })
        try:
            r = fetch_url(session, f"{full_url}/readme.html", timeout=5)
            if r.status_code == 200 and "wordpress" in r.text.lower():
                vulns.append({
                    "severity": "LOW",
                    "title": "WordPress Readme Exposed",
                    "description": "/readme.html is accessible and reveals WordPress version.",
                    "remediation": "Delete or block access to readme.html"
                })
        except:
            pass
    return vulns

def check_s3_buckets(html):
    vulns = []
    buckets = re.findall(r'https?://([a-z0-9.-]+\.s3[\.\-][a-z0-9-]+\.amazonaws\.com)', html, re.I)
    if buckets:
        vulns.append({
            "severity": "MEDIUM",
            "title": "AWS S3 Bucket Reference Found",
            "description": f"S3 bucket(s) referenced: {', '.join(list(set(buckets))[:2])}. Verify bucket permissions are not public.",
            "remediation": "Ensure S3 buckets are private and use IAM policies correctly"
        })
    return vulns

def check_sri(html):
    vulns = []
    scripts = re.findall(r'<script[^>]+src=["\'](https?://[^"\']+)["\'][^>]*>', html, re.I)
    missing_sri = []
    for src in scripts:
        if "integrity=" not in html[html.find(src)-100:html.find(src)+len(src)+50]:
            missing_sri.append(src)
    if len(missing_sri) >= 2:
        vulns.append({
            "severity": "LOW",
            "title": "Missing Subresource Integrity (SRI)",
            "description": f"{len(missing_sri)} external scripts loaded without integrity hashes. If CDN compromised, malicious code executes.",
            "remediation": "Add integrity and crossorigin attributes to external resources"
        })
    return vulns

def check_waf(headers, html):
    vulns = []
    waf_signs = ["cloudflare", "sucuri", "incapsula", "akamai", "aws waf", "barracuda", "f5", "imperva"]
    combined = str(headers).lower() + html.lower()
    for waf in waf_signs:
        if waf in combined:
            vulns.append({
                "severity": "INFO",
                "title": f"WAF Detected: {waf.title()}",
                "description": f"{waf.title()} Web Application Firewall detected. Provides basic protection but not impenetrable.",
                "remediation": "Ensure WAF rules are regularly updated. Do not rely solely on WAF for security."
            })
            break
    return vulns

def check_crossdomain(session, full_url):
    vulns = []
    for file in ["/crossdomain.xml", "/clientaccesspolicy.xml"]:
        try:
            r = fetch_url(session, f"{full_url}{file}", timeout=5)
            if r.status_code == 200 and ("allow-access-from" in r.text or "domain=\"*\"" in r.text):
                vulns.append({
                    "severity": "MEDIUM",
                    "title": f"Insecure {file}",
                    "description": f"{file} allows cross-domain requests. May enable cross-site attacks.",
                    "remediation": f"Restrict {file} to specific trusted domains only"
                })
        except:
            pass
    return vulns

def check_vulnerabilities(session, full_url, domain, headers, html):
    vulns = []
    
    if "Strict-Transport-Security" not in headers:
        vulns.append({
            "severity": "HIGH",
            "title": "Missing HSTS Header",
            "description": "HTTP Strict Transport Security not enabled. Site vulnerable to SSL stripping attacks.",
            "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
        })
    if "X-Frame-Options" not in headers and "Content-Security-Policy" not in headers:
        vulns.append({
            "severity": "MEDIUM",
            "title": "Clickjacking Possible",
            "description": "X-Frame-Options missing. Site can be embedded in malicious iframes.",
            "remediation": "Add: X-Frame-Options: DENY or SAMEORIGIN"
        })
    if "X-Content-Type-Options" not in headers:
        vulns.append({
            "severity": "LOW",
            "title": "MIME Sniffing Enabled",
            "description": "Browser may interpret files differently than declared Content-Type.",
            "remediation": "Add: X-Content-Type-Options: nosniff"
        })
    if "Content-Security-Policy" not in headers:
        vulns.append({
            "severity": "MEDIUM",
            "title": "Missing Content Security Policy",
            "description": "No CSP defined. Vulnerable to XSS and data injection attacks.",
            "remediation": "Add: Content-Security-Policy with strict directives"
        })
    if "Referrer-Policy" not in headers:
        vulns.append({
            "severity": "LOW",
            "title": "Referrer Policy Missing",
            "description": "Sensitive URL data may leak to third-party sites.",
            "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
        })
    if "Permissions-Policy" not in headers and "Feature-Policy" not in headers:
        vulns.append({
            "severity": "LOW",
            "title": "Missing Permissions Policy",
            "description": "Browser features (camera, mic, geolocation) not restricted.",
            "remediation": "Add: Permissions-Policy with restricted feature list"
        })
    
    server = headers.get("Server", "")
    powered = headers.get("X-Powered-By", "")
    if server and server != "Unknown":
        vulns.append({
            "severity": "INFO",
            "title": "Server Version Disclosure",
            "description": f"Server header reveals: {server}",
            "remediation": "Hide Server header in web server config"
        })
    if powered:
        vulns.append({
            "severity": "INFO",
            "title": "Technology Disclosure",
            "description": f"X-Powered-By reveals: {powered}",
            "remediation": "Remove X-Powered-By header"
        })
    
    sensitive_paths = [
        "/.env", "/.git/HEAD", "/phpinfo.php", "/info.php", 
        "/.htaccess", "/backup.zip", "/db.sql", "/config.php",
        "/admin.zip", "/wp-config.php.bak", "/.svn/entries",
        "/api/", "/swagger.json", "/openapi.json", "/graphql",
        "/.DS_Store", "/web.config", "/config.json", "/package.json",
        "/composer.json", "/Dockerfile", "/docker-compose.yml"
    ]
    for path in sensitive_paths:
        try:
            r = fetch_url(session, f"{full_url}{path}", timeout=5)
            if r.status_code == 200:
                content_preview = r.text[:100]
                if any(x in content_preview for x in ["DB_PASSWORD", "APP_KEY", "ref:", "<?php", "swagger", "openapi", "version", "dependencies"]):
                    vulns.append({
                        "severity": "CRITICAL",
                        "title": f"Exposed Sensitive File: {path}",
                        "description": f"File accessible at {path} - may contain credentials or source code.",
                        "remediation": f"Restrict access to {path} or remove from production"
                    })
                elif len(r.text) > 50:
                    vulns.append({
                        "severity": "HIGH",
                        "title": f"Accessible Path: {path}",
                        "description": f"{path} returns 200 OK. Verify if sensitive data is exposed.",
                        "remediation": f"Block {path} via web server rules"
                    })
        except:
            pass
    
    try:
        r = fetch_url(session, f"{full_url}/images/", timeout=5)
        if "Index of" in r.text or "Directory Listing" in r.text:
            vulns.append({
                "severity": "MEDIUM",
                "title": "Directory Listing Enabled",
                "description": "Server shows file listing when no index file present.",
                "remediation": "Disable autoindex in web server config"
            })
    except:
        pass
    
    set_cookie = headers.get("Set-Cookie", "")
    if set_cookie:
        if "HttpOnly" not in set_cookie:
            vulns.append({
                "severity": "MEDIUM",
                "title": "Cookie Missing HttpOnly Flag",
                "description": "Session cookies accessible via JavaScript. XSS can steal sessions.",
                "remediation": "Add HttpOnly flag to session cookies"
            })
        if "Secure" not in set_cookie:
            vulns.append({
                "severity": "MEDIUM",
                "title": "Cookie Missing Secure Flag",
                "description": "Cookies sent over HTTP. Vulnerable to session hijacking on insecure networks.",
                "remediation": "Add Secure flag to cookies"
            })
        if "SameSite" not in set_cookie:
            vulns.append({
                "severity": "LOW",
                "title": "Cookie Missing SameSite Attribute",
                "description": "Vulnerable to CSRF attacks via cross-site requests.",
                "remediation": "Add SameSite=Strict or SameSite=Lax"
            })
    
    acao = headers.get("Access-Control-Allow-Origin", "")
    if acao == "*":
        vulns.append({
            "severity": "HIGH",
            "title": "CORS Wildcard Enabled",
            "description": "Access-Control-Allow-Origin: * allows any website to make authenticated requests.",
            "remediation": "Restrict CORS to specific trusted domains only"
        })
    
    if "wordpress" in html.lower() or "wp-content" in html.lower():
        try:
            r = fetch_url(session, f"{full_url}/wp-json/wp/v2/users", timeout=5)
            if r.status_code == 200 and '"id"' in r.text:
                vulns.append({
                    "severity": "MEDIUM",
                    "title": "WordPress User Enumeration",
                    "description": "REST API exposes user list at /wp-json/wp/v2/users",
                    "remediation": "Disable REST API user endpoints or require authentication"
                })
        except:
            pass
    
    try:
        r = fetch_url(session, f"{full_url}/robots.txt", timeout=5)
        if r.status_code == 200:
            if any(x in r.text.lower() for x in ["admin", "backup", "config", ".env", "private"]):
                vulns.append({
                    "severity": "INFO",
                    "title": "Sensitive Paths in robots.txt",
                    "description": "robots.txt reveals sensitive directories that attackers can target.",
                    "remediation": "Do not list sensitive paths in robots.txt"
                })
    except:
        pass

    vulns.extend(check_http_methods(session, full_url))
    vulns.extend(check_mixed_content(full_url, html))
    vulns.extend(check_leaked_secrets(html))
    vulns.extend(check_internal_ips(html))
    vulns.extend(check_html_comments(html))
    vulns.extend(check_security_txt(session, full_url))
    vulns.extend(check_open_redirect(session, full_url))
    vulns.extend(check_sql_errors(html))
    vulns.extend(check_stack_traces(html))
    vulns.extend(check_jquery_version(html))
    vulns.extend(check_wp_version(session, full_url, html))
    vulns.extend(check_s3_buckets(html))
    vulns.extend(check_sri(html))
    vulns.extend(check_waf(headers, html))
    vulns.extend(check_crossdomain(session, full_url))
    
    return vulns

def get_website_details(url: str):
    domain = url.replace("https://","").replace("http://","").replace("www.","").strip("/").split("/")[0]
    full_url = f"https://{domain}"

    result = {
        "domain": domain,
        "scan_info": {},
        "basic": {"is_online": False, "note": "Scanning..."},
        "whois": {},
        "dns": {},
        "ssl": {},
        "technology": {"stack": []},
        "subdomains": [],
        "security_headers": {},
        "pages": {"admin_pages": [], "emails_found": [], "links_found": [], "robots_txt": "Not checked", "sitemap_found": False},
        "emails_found": [],
        "dns_subdomains": [],
        "vulnerabilities": [],
        "risk_score": 0,
        "risk_level": "LOW"
    }

    session = get_session(use_tor=True)
    tor_works = False
    tor_ip_info = {}
    
    try:
        tor_ip_info = get_my_ip(session)
        if "error" not in tor_ip_info:
            tor_works = True
    except:
        pass

    result["scan_info"] = {
        "scanner_ip_hidden": tor_works,
        "detected_ip": tor_ip_info.get("ip", "Unknown"),
        "detected_country": tor_ip_info.get("country", "Unknown"),
        "via": "Tor Network",
        "warning": "Your real IP is hidden. Scanning anonymously via Tor."
    }

    page_html = None
    used_tor = False
    direct_session = None
    
    if tor_works:
        try:
            r = fetch_url(session, full_url, timeout=15)
            page_html = r.text
            used_tor = True
        except:
            pass

    if page_html is None:
        try:
            direct_session = get_session(use_tor=False)
            r = fetch_url(direct_session, full_url, timeout=10)
            page_html = r.text
            try:
                direct_ip = get_my_ip(direct_session)
                result["scan_info"] = {
                    "scanner_ip_hidden": False,
                    "detected_ip": direct_ip.get("ip", "Unknown"),
                    "detected_country": direct_ip.get("country", "Unknown"),
                    "via": "DIRECT CONNECTION (IP EXPOSED)",
                    "warning": "⚠️ TOR BLOCKED BY TARGET! Fallback to direct connection. Your real IP is visible!"
                }
            except:
                result["scan_info"]["warning"] = "⚠️ TOR FAILED! Used direct connection. IP may be exposed."
        except Exception as e:
            result["basic"] = {
                "is_online": False,
                "error": f"Connection failed: {str(e)}",
                "note": "Website unreachable."
            }

    if page_html:
        soup = BeautifulSoup(page_html, "html.parser")
        h = r.headers

        result["basic"] = {
            "ip_address": "Hidden via Tor" if used_tor else "DIRECT (Exposed)",
            "status_code": r.status_code,
            "server": h.get("Server", "Unknown"),
            "response_time": f"{r.elapsed.total_seconds():.2f}s",
            "content_type": h.get("Content-Type", ""),
            "page_title": soup.title.string.strip() if soup.title else "No title",
            "is_online": True,
            "content_length": h.get("Content-Length", "Unknown"),
            "x_powered_by": h.get("X-Powered-By", "Hidden"),
        }

        result["security_headers"] = {
            "https": True,
            "hsts": "Strict-Transport-Security" in h,
            "xframe": "X-Frame-Options" in h,
            "xss_protection": "X-XSS-Protection" in h,
            "content_security": "Content-Security-Policy" in h,
            "x_content_type": "X-Content-Type-Options" in h,
            "referrer_policy": "Referrer-Policy" in h,
            "permissions": "Permissions-Policy" in h,
            "x_powered_by": h.get("X-Powered-By", "Hidden"),
        }

        tech = []
        page_text = page_html.lower()
        if "wordpress" in page_text or "wp-content" in page_text: tech.append("WordPress")
        if "joomla" in page_text: tech.append("Joomla")
        if "drupal" in page_text: tech.append("Drupal")
        if "shopify" in page_text: tech.append("Shopify")
        if "wix.com" in page_text: tech.append("Wix")
        if "jquery" in page_text: tech.append("jQuery")
        if "react" in page_text: tech.append("React.js")
        if "angular" in page_text: tech.append("Angular")
        if "vue" in page_text: tech.append("Vue.js")
        if "bootstrap" in page_text: tech.append("Bootstrap")
        if "tailwind" in page_text: tech.append("Tailwind CSS")
        if "laravel" in page_text: tech.append("Laravel")
        if "django" in page_text: tech.append("Django")
        if "nginx" in h.get("Server","").lower(): tech.append("Nginx")
        if "apache" in h.get("Server","").lower(): tech.append("Apache")
        if "cloudflare" in h.get("Server","").lower(): tech.append("Cloudflare")
        if "iis" in h.get("Server","").lower(): tech.append("IIS")
        if "php" in h.get("X-Powered-By","").lower(): tech.append("PHP")
        if "asp.net" in h.get("X-Powered-By","").lower(): tech.append("ASP.NET")
        if "express" in h.get("X-Powered-By","").lower(): tech.append("Express.js")
        if "google-analytics" in page_text: tech.append("Google Analytics")
        result["technology"]["stack"] = list(set(tech))

        all_links = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith("/") and len(href) > 1:
                all_links.append(href.split("?")[0])
            elif domain in href:
                path = href.replace(full_url,"").replace(f"http://{domain}","").replace(f"https://{domain}","")
                if path:
                    all_links.append(path.split("?")[0])
        result["pages"]["links_found"] = list(set(all_links))[:30]

        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', page_html)
        result["emails_found"] = list(set(emails))[:10]
        result["pages"]["emails_found"] = result["emails_found"]

        session_to_use = session if used_tor else direct_session
        vulns = check_vulnerabilities(session_to_use, full_url, domain, h, page_text)
        result["vulnerabilities"] = vulns

    if page_html:
        try:
            session_to_use = session if used_tor else direct_session
            robots = fetch_url(session_to_use, f"{full_url}/robots.txt", timeout=10)
            if robots.status_code == 200:
                result["pages"]["robots_txt"] = robots.text[:1500]
                disallowed = re.findall(r'Disallow:\s*(.+)', robots.text)
                result["pages"]["disallowed_paths"] = disallowed[:20]
            else:
                result["pages"]["robots_txt"] = f"Status: {robots.status_code}"
        except Exception as e:
            result["pages"]["robots_txt"] = f"Error: {str(e)}"

    if page_html:
        try:
            session_to_use = session if used_tor else direct_session
            sitemap = fetch_url(session_to_use, f"{full_url}/sitemap.xml", timeout=10)
            if sitemap.status_code == 200:
                result["pages"]["sitemap_found"] = True
                sitemap_soup = BeautifulSoup(sitemap.text, "xml")
                urls = [loc.text for loc in sitemap_soup.find_all("loc")][:20]
                result["pages"]["sitemap_urls"] = urls
        except:
            result["pages"]["sitemap_found"] = False

    if page_html:
        admin_paths = ["/admin", "/login", "/wp-admin", "/administrator", "/dashboard", "/cpanel", "/phpmyadmin", "/manager", "/admin/login", "/user/login", "/wp-login.php", "/admin.php"]
        admin_pages = []
        session_to_use = session if used_tor else direct_session
        for path in admin_paths:
            try:
                pr = fetch_url(session_to_use, f"{full_url}{path}", timeout=6)
                if pr.status_code in [200, 401, 403]:
                    admin_pages.append({"path": path, "status": pr.status_code, "note": "Found!" if pr.status_code == 200 else "Protected"})
            except:
                pass
        result["pages"]["admin_pages"] = admin_pages
    else:
        result["pages"]["admin_pages"] = [{"path": "N/A", "status": 0, "note": "Website unreachable"}]

    try:
        w = whois.whois(domain)
        result["whois"] = {
            "registrar": str(w.registrar) if w.registrar else "Unknown",
            "owner_name": str(w.name) if hasattr(w,"name") and w.name else "Hidden",
            "owner_email": str(w.emails) if hasattr(w,"emails") and w.emails else "Hidden",
            "owner_org": str(w.org) if hasattr(w,"org") and w.org else "Unknown",
            "creation_date": str(w.creation_date[0] if isinstance(w.creation_date,list) else w.creation_date),
            "expiry_date": str(w.expiration_date[0] if isinstance(w.expiration_date,list) else w.expiration_date),
            "updated_date": str(w.updated_date[0] if isinstance(w.updated_date,list) else w.updated_date),
            "name_servers": list(w.name_servers) if w.name_servers else [],
            "country": str(w.country) if hasattr(w,"country") and w.country else "Unknown",
            "dnssec": str(w.dnssec) if hasattr(w,"dnssec") and w.dnssec else "Unknown",
        }
    except Exception as e:
        result["whois"]["error"] = str(e)

    try:
        dns_records = {}
        for rtype in ["A","AAAA","MX","NS","TXT","CNAME","SOA","CAA"]:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                dns_records[rtype] = [str(r) for r in answers]
            except:
                dns_records[rtype] = []
        result["dns"] = dns_records
    except Exception as e:
        result["dns"]["error"] = str(e)

    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(5)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        conn.close()
        result["ssl"] = {
            "valid": True,
            "issued_to": dict(x[0] for x in cert["subject"]).get("commonName",""),
            "issued_by": dict(x[0] for x in cert["issuer"]).get("organizationName",""),
            "valid_from": cert["notBefore"],
            "valid_until": cert["notAfter"],
            "version": cert.get("version",""),
            "san": [x[1] for x in cert.get("subjectAltName",[])],
        }
    except Exception as e:
        result["ssl"] = {"valid": False, "error": str(e)}

    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=10)
        if r.status_code == 200:
            certs = r.json()
            subdomains = list(set([
                c["name_value"].lower().replace("*.","").strip()
                for c in certs
                if domain in c["name_value"] and "@" not in c["name_value"]
            ]))[:30]
            result["subdomains"] = sorted(list(set(subdomains)))
            result["subdomain_count"] = len(result["subdomains"])
    except:
        result["subdomains"] = []
        result["subdomain_count"] = 0

    try:
        common_subs = ["www","mail","ftp","smtp","pop","imap","webmail","admin","blog","dev","api","app","portal","secure","vpn"]
        dns_subs = []
        for sub in common_subs:
            try:
                full = f"{sub}.{domain}"
                ip = socket.gethostbyname(full)
                if full not in result["subdomains"]:
                    dns_subs.append({"subdomain": full, "ip": ip})
            except:
                pass
        result["dns_subdomains"] = dns_subs
    except:
        result["dns_subdomains"] = []

    risk = 0
    if not result["security_headers"].get("hsts"): risk += 15
    if not result["security_headers"].get("xframe"): risk += 10
    if not result["security_headers"].get("content_security"): risk += 15
    if not result["ssl"].get("valid"): risk += 30
    if result["pages"].get("admin_pages"): risk += 20
    if result["emails_found"]: risk += 10
    
    for v in result["vulnerabilities"]:
        if v["severity"] == "CRITICAL": risk += 25
        elif v["severity"] == "HIGH": risk += 15
        elif v["severity"] == "MEDIUM": risk += 10
        elif v["severity"] == "LOW": risk += 5
    
    result["vulnerability_count"] = len(result["vulnerabilities"])
    result["critical_count"] = sum(1 for v in result["vulnerabilities"] if v["severity"] == "CRITICAL")
    result["high_count"] = sum(1 for v in result["vulnerabilities"] if v["severity"] == "HIGH")
    
    result["risk_score"] = min(100, risk)
    result["risk_level"] = "CRITICAL" if risk >= 75 else "HIGH" if risk >= 50 else "MEDIUM" if risk >= 25 else "LOW"

    return result
