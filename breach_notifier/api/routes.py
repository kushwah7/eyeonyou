import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import APIRouter, UploadFile, File
from crawler.leakcheck import check_email_leakcheck
from crawler.tor_crawler import verify_tor_connection, search_darkweb_breach
from analyzer.risk_score import analyze_all_breaches
from analyzer.ai_context import generate_ai_advice
from notifier.email_alert import send_breach_alert

router = APIRouter()

@router.get("/health")
def health_check():
    return {
        "status": "ok",
        "message": "DarkShield API Running! 🔐",
        "tools": ["email", "ip", "website", "image", "hash", "log"]
    }

@router.get("/tor/status")
def tor_status():
    return verify_tor_connection()

@router.get("/check/email/{email}")
def check_email(email: str):
    lc = check_email_leakcheck(email)
    breaches = lc.get("breaches", [])
    analysis = analyze_all_breaches(breaches)
    ai_advice = generate_ai_advice(analysis)
    email_status = {"sent": False}
    if analysis.get("total_breaches", 0) > 0:
        email_status = send_breach_alert(email, {"analysis": analysis, "ai_advice": ai_advice})
    return {
        "query": email,
        "type": "email",
        "analysis": analysis,
        "ai_advice": ai_advice,
        "alert_sent": email_status
    }

@router.get("/darkweb/search/{email}")
def darkweb_search(email: str):
    return search_darkweb_breach(email)

from crawler.ip_lookup import get_ip_details

@router.get("/lookup/ip/{ip}")
def ip_lookup(ip: str):
    return get_ip_details(ip)

from crawler.website_osint import get_website_details

@router.get("/lookup/website")
def website_lookup(url: str):
    return get_website_details(url)

from crawler.image_osint import get_image_details
from crawler.image_master import analyze_image_complete
from crawler.face_osint import analyze_face

@router.post("/lookup/image")
async def image_lookup(file: UploadFile = File(...)):
    image_bytes = await file.read()
    return get_image_details(image_bytes, file.filename)

@router.post("/lookup/image/full")
async def image_full_lookup(file: UploadFile = File(...)):
    image_bytes = await file.read()
    return analyze_image_complete(image_bytes, file.filename)

@router.post("/lookup/face")
async def face_lookup(file: UploadFile = File(...)):
    image_bytes = await file.read()
    return analyze_face(image_bytes, file.filename)

from crawler.hash_analyzer import analyze_hash

@router.get("/lookup/hash")
def hash_lookup(hash_str: str):
    return analyze_hash(hash_str)

from crawler.log_analyzer import parse_log_file

@router.post("/lookup/log")
async def log_lookup(file: UploadFile = File(...)):
    content = await file.read()
    log_text = content.decode("utf-8", errors="ignore")
    return parse_log_file(log_text)
