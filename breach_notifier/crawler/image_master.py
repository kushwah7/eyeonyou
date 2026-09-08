import io
import os
import re
import struct
import hashlib
import base64
import math
from datetime import datetime
from PIL import Image, ExifTags
import numpy as np

try:
    import pytesseract
    TESSERACT_AVAILABLE = True
except ImportError:
    TESSERACT_AVAILABLE = False

try:
    from pyzbar.pyzbar import decode as qr_decode
    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False


def sanitize_for_json(obj):
    """Recursively replace NaN/Inf with 0.0 so JSON can serialize it"""
    if isinstance(obj, dict):
        return {k: sanitize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [sanitize_for_json(item) for item in obj]
    elif isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            return 0.0
        return obj
    return obj


def get_exif_data(image_bytes, filename):
    result = {
        "filename": filename,
        "file_size": len(image_bytes),
        "file_hash": hashlib.sha256(image_bytes).hexdigest()[:16],
        "basic": {},
        "device": {},
        "camera": {},
        "datetime": {},
        "location": {"location_found": False}
    }
    try:
        img = Image.open(io.BytesIO(image_bytes))
        result["basic"] = {
            "format": img.format,
            "mode": img.mode,
            "width": img.width,
            "height": img.height,
            "megapixels": round((img.width * img.height) / 1000000, 2)
        }
        exif = img._getexif()
        if exif:
            exif_data = {}
            for tag_id, value in exif.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                exif_data[tag] = str(value)
            result["device"] = {
                "make": exif_data.get("Make", "Unknown"),
                "model": exif_data.get("Model", "Unknown"),
                "software": exif_data.get("Software", "Unknown")
            }
            result["camera"] = {
                "iso": exif_data.get("ISOSpeedRatings", "Unknown"),
                "aperture": exif_data.get("FNumber", "Unknown"),
                "shutter": exif_data.get("ExposureTime", "Unknown"),
                "focal_length": exif_data.get("FocalLength", "Unknown")
            }
            dt = exif_data.get("DateTime", "Unknown")
            result["datetime"] = {
                "created": dt,
                "modified": exif_data.get("DateTimeDigitized", dt)
            }
            gps = exif.get(34853)
            if gps:
                try:
                    lat = convert_gps(gps.get(2), gps.get(1))
                    lon = convert_gps(gps.get(4), gps.get(3))
                    result["location"] = {
                        "location_found": True,
                        "latitude": lat,
                        "longitude": lon,
                        "map_url": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}",
                        "google_maps": f"https://www.google.com/maps?q={lat},{lon}"
                    }
                except:
                    pass
    except Exception as e:
        result["error"] = str(e)
    return result


def convert_gps(coords, ref):
    d, m, s = coords
    decimal = d + m/60 + s/3600
    if ref in ['S', 'W']:
        decimal = -decimal
    return round(decimal, 6)


def get_reverse_search_links(image_bytes):
    return {
        "google_lens": "https://lens.google.com/uploadbyurl",
        "yandex": "https://yandex.com/images/",
        "bing": "https://www.bing.com/visualsearch",
        "tineye": "https://tineye.com/",
        "pimeyes": "https://pimeyes.com/en",
        "facecheck_id": "https://facecheck.id/"
    }


def extract_ocr_text(image_bytes):
    if not TESSERACT_AVAILABLE:
        return {"available": False, "text": "Install pytesseract: pip install pytesseract"}
    try:
        img = Image.open(io.BytesIO(image_bytes))
        gray = img.convert('L')
        text = pytesseract.image_to_string(gray)
        return {
            "available": True,
            "text": text.strip(),
            "word_count": len(text.split()),
            "has_text": len(text.strip()) > 0
        }
    except Exception as e:
        return {"available": True, "error": str(e), "text": ""}


def extract_qr_codes(image_bytes):
    if not QRCODE_AVAILABLE:
        return {"available": False, "codes": [], "note": "Install pyzbar: pip install pyzbar"}
    try:
        img = Image.open(io.BytesIO(image_bytes))
        codes = qr_decode(img)
        results = []
        for code in codes:
            results.append({
                "type": code.type,
                "data": code.data.decode('utf-8'),
                "rect": str(code.rect)
            })
        return {
            "available": True,
            "found": len(results) > 0,
            "total": len(results),
            "codes": results
        }
    except Exception as e:
        return {"available": True, "error": str(e), "codes": []}


def error_level_analysis(image_bytes):
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
        buffer = io.BytesIO()
        img.save(buffer, format='JPEG', quality=90)
        buffer.seek(0)
        resaved = Image.open(buffer)
        
        img_np = np.array(img, dtype=np.float64)
        resaved_np = np.array(resaved, dtype=np.float64)
        
        diff = np.abs(img_np - resaved_np)
        
        mean_diff = 0.0
        max_diff = 0.0
        
        if diff.size > 0:
            mean_val = np.nanmean(diff)
            max_val = np.nanmax(diff)
            if not (math.isnan(mean_val) or math.isinf(mean_val)):
                mean_diff = float(mean_val)
            if not (math.isnan(max_val) or math.isinf(max_val)):
                max_diff = float(max_val)
        
        if mean_diff > 5:
            manipulation = "HIGH"
            color = "#ff003c"
        elif mean_diff > 2:
            manipulation = "MEDIUM"
            color = "#ffaa00"
        elif mean_diff > 0.5:
            manipulation = "LOW"
            color = "#00ff88"
        else:
            manipulation = "NONE"
            color = "#00ccff"
        
        return {
            "performed": True,
            "mean_difference": round(mean_diff, 2),
            "max_difference": round(max_diff, 2),
            "manipulation_level": manipulation,
            "color": color,
            "note": "ELA detects regions with different compression levels — signs of editing"
        }
    except Exception as e:
        return {"performed": False, "error": str(e)}


def check_hidden_content(image_bytes):
    result = {
        "hidden_text": [],
        "suspicious_strings": [],
        "embedded_files": [],
        "virus_indicators": [],
        "steganography_detected": False,
        "risk": "LOW",
        "risk_score": 0
    }
    try:
        raw = image_bytes.decode('latin-1', errors='replace')
        strings = re.findall(r'[ -~]{4,}', raw)
        suspicious_keywords = [
            'password','passwd','secret','token','api_key',
            'malware','virus','trojan','hack','exploit',
            'eval(','exec(','system(','cmd','powershell',
            'http://','https://','ftp://','bitcoin',
            'SELECT','DROP TABLE','<script','javascript:'
        ]
        for s in strings:
            s_lower = s.lower()
            for kw in suspicious_keywords:
                if kw.lower() in s_lower:
                    result["suspicious_strings"].append({
                        "found": s[:100],
                        "keyword": kw
                    })
                    break
        
        # PNG chunks
        if image_bytes[:8] == b'\x89PNG\r\n\x1a\n':
            offset = 8
            while offset < len(image_bytes)-12:
                try:
                    length = struct.unpack('>I', image_bytes[offset:offset+4])[0]
                    chunk_type = image_bytes[offset+4:offset+8].decode('ascii','replace')
                    standard = ['IHDR','IDAT','IEND','PLTE','tEXt','zTXt','iTXt','cHRM','gAMA','sRGB','bKGD','pHYs','sBIT','tIME']
                    if chunk_type not in standard:
                        result["embedded_files"].append({
                            "type": f"Unknown PNG chunk: {chunk_type}",
                            "size": length,
                            "suspicious": True
                        })
                    if chunk_type == 'tEXt':
                        text_data = image_bytes[offset+8:offset+8+length]
                        result["hidden_text"].append(text_data.decode('latin-1','replace'))
                    offset += 12 + length
                except:
                    break
        
        # JPEG comments
        if image_bytes[:2] == b'\xff\xd8':
            i = 2
            while i < len(image_bytes)-2:
                if image_bytes[i] == 0xff:
                    marker = image_bytes[i+1]
                    if marker == 0xfe:
                        try:
                            length = struct.unpack('>H', image_bytes[i+2:i+4])[0]
                            comment = image_bytes[i+4:i+2+length].decode('latin-1','replace')
                            result["hidden_text"].append(f"JPEG Comment: {comment}")
                        except:
                            pass
                    try:
                        length = struct.unpack('>H', image_bytes[i+2:i+4])[0]
                        i += 2 + length
                    except:
                        i += 2
                else:
                    i += 1
        
        # File signatures
        file_signatures = {
            b'PK\x03\x04': 'ZIP file embedded',
            b'Rar!': 'RAR file embedded',
            b'%PDF': 'PDF file embedded',
            b'MZ': 'EXE/DLL embedded (DANGEROUS!)',
            b'\x7fELF': 'Linux executable embedded',
            b'<?php': 'PHP code embedded',
            b'<script': 'JavaScript embedded',
        }
        for sig, desc in file_signatures.items():
            if sig in image_bytes[100:]:
                result["embedded_files"].append({
                    "type": desc,
                    "dangerous": 'DANGEROUS' in desc or 'code' in desc
                })
                if 'DANGEROUS' in desc or 'code' in desc:
                    result["virus_indicators"].append(desc)
        
        # LSB check
        try:
            img = Image.open(io.BytesIO(image_bytes)).convert('RGB')
            pixels = np.array(img)
            if pixels.size > 0:
                lsb = pixels[:,:,0] & 1
                ratio = float(np.mean(lsb))
                if math.isnan(ratio) or math.isinf(ratio):
                    ratio = 0.0
                if 0.47 <= ratio <= 0.53:
                    result["steganography_detected"] = True
                    result["hidden_text"].append(f"LSB steganography detected (ratio: {ratio:.3f})")
        except:
            pass
        
        # Risk score
        risk_score = 0
        if result["virus_indicators"]: risk_score += 80
        if result["embedded_files"]: risk_score += 40
        if result["steganography_detected"]: risk_score += 30
        if result["suspicious_strings"]: risk_score += 20
        if result["hidden_text"]: risk_score += 10
        result["risk_score"] = min(100, risk_score)
        result["risk"] = (
            "CRITICAL" if risk_score>=75 else
            "HIGH" if risk_score>=50 else
            "MEDIUM" if risk_score>=25 else
            "LOW"
        )
    except Exception as e:
        result["error"] = str(e)
    return result


def describe_image_content(image_bytes):
    try:
        from groq import Groq
        import config
        client = Groq(api_key=config.GROQ_API_KEY)
        prompt = """Analyze this image and describe:
1. What objects/items are visible
2. Any text/signs visible
3. Any faces or people
4. Any suspicious or notable content
5. Overall scene description
Keep under 100 words."""
        response = client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[{"role": "user", "content": prompt}]
        )
        return {
            "ai_description": response.choices[0].message.content,
            "method": "AI Analysis"
        }
    except Exception as e:
        return {
            "ai_description": "AI image description unavailable. Ensure Groq API is working.",
            "error": str(e),
            "method": "fallback"
        }


def analyze_image_complete(image_bytes, filename):
    exif = get_exif_data(image_bytes, filename)
    reverse = get_reverse_search_links(image_bytes)
    ocr = extract_ocr_text(image_bytes)
    qr = extract_qr_codes(image_bytes)
    ela = error_level_analysis(image_bytes)
    hidden = check_hidden_content(image_bytes)
    ai_desc = describe_image_content(image_bytes)
    
    result = {
        "basic": exif.get("basic", {}),
        "device": exif.get("device", {}),
        "camera": exif.get("camera", {}),
        "datetime": exif.get("datetime", {}),
        "location": exif.get("location", {"location_found": False}),
        "reverse_search": reverse,
        "ocr": ocr,
        "qr_codes": qr,
        "ela": ela,
        "hidden": hidden,
        "ai_description": ai_desc,
        "filename": filename,
        "scan_time": datetime.now().isoformat()
    }
    
    # BULLETPROOF: remove any NaN/Inf from entire response
    return sanitize_for_json(result)
