import exifread
import json
import os
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import io

def get_decimal_coordinates(info):
    """Convert GPS coordinates to decimal format"""
    try:
        def convert(value):
            d, m, s = [float(x.num) / float(x.den) for x in value.values]
            return d + (m / 60.0) + (s / 3600.0)

        lat = convert(info.get("GPSLatitude"))
        lon = convert(info.get("GPSLongitude"))

        if info.get("GPSLatitudeRef") == "S":
            lat = -lat
        if info.get("GPSLongitudeRef") == "W":
            lon = -lon

        return lat, lon
    except:
        return None, None


def get_image_details(image_bytes: bytes, filename: str = "image"):
    """Extract complete image metadata"""

    result = {
        "filename": filename,
        "basic": {},
        "device": {},
        "camera": {},
        "location": {},
        "datetime": {},
        "software": {},
        "risk_score": 0,
        "risk_level": "LOW"
    }

    # 1 — Basic file info using Pillow
    try:
        img = Image.open(io.BytesIO(image_bytes))
        result["basic"] = {
            "format":     img.format,
            "mode":       img.mode,
            "width":      img.size[0],
            "height":     img.size[1],
            "file_size":  f"{len(image_bytes) / 1024:.2f} KB",
            "megapixels": f"{(img.size[0] * img.size[1]) / 1000000:.2f} MP"
        }
    except Exception as e:
        result["basic"]["error"] = str(e)

    # 2 — EXIF data using exifread
    try:
        tags = exifread.process_file(
            io.BytesIO(image_bytes),
            details=True
        )

        # Device info
        result["device"] = {
            "make":             str(tags.get("Image Make", "Unknown")),
            "model":            str(tags.get("Image Model", "Unknown")),
            "software":         str(tags.get("Image Software", "Unknown")),
            "artist":           str(tags.get("Image Artist", "Unknown")),
            "copyright":        str(tags.get("Image Copyright", "Unknown")),
        }

        # Camera settings
        result["camera"] = {
            "aperture":         str(tags.get("EXIF FNumber", "Unknown")),
            "exposure_time":    str(tags.get("EXIF ExposureTime", "Unknown")),
            "iso":              str(tags.get("EXIF ISOSpeedRatings", "Unknown")),
            "focal_length":     str(tags.get("EXIF FocalLength", "Unknown")),
            "flash":            str(tags.get("EXIF Flash", "Unknown")),
            "white_balance":    str(tags.get("EXIF WhiteBalance", "Unknown")),
            "exposure_mode":    str(tags.get("EXIF ExposureMode", "Unknown")),
            "metering_mode":    str(tags.get("EXIF MeteringMode", "Unknown")),
            "orientation":      str(tags.get("Image Orientation", "Unknown")),
            "color_space":      str(tags.get("EXIF ColorSpace", "Unknown")),
            "scene_type":       str(tags.get("EXIF SceneCaptureType", "Unknown")),
        }

        # Date and time
        result["datetime"] = {
            "taken":            str(tags.get("EXIF DateTimeOriginal", "Unknown")),
            "digitized":        str(tags.get("EXIF DateTimeDigitized", "Unknown")),
            "modified":         str(tags.get("Image DateTime", "Unknown")),
        }

        # Software
        result["software"] = {
            "processing_software": str(tags.get("Image ProcessingSoftware", "Unknown")),
            "software":            str(tags.get("Image Software", "Unknown")),
        }

        # GPS Location
        gps_data = {}
        for tag, value in tags.items():
            if "GPS" in str(tag):
                gps_data[str(tag).replace("GPS ", "")] = value

        if gps_data:
            lat, lon = get_decimal_coordinates(gps_data)
            if lat and lon:
                result["location"] = {
                    "latitude":      lat,
                    "longitude":     lon,
                    "altitude":      str(gps_data.get("GPSAltitude", "Unknown")),
                    "gps_speed":     str(gps_data.get("GPSSpeed", "Unknown")),
                    "map_url":       f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=15/{lat}/{lon}",
                    "google_maps":   f"https://www.google.com/maps?q={lat},{lon}",
                    "location_found": True
                }

                # Get address from coordinates
                try:
                    geo = requests.get(
                        f"https://nominatim.openstreetmap.org/reverse",
                        params={
                            "lat": lat,
                            "lon": lon,
                            "format": "json"
                        },
                        headers={"User-Agent": "EyeOnYou-OSINT"},
                        timeout=10
                    )
                    geo_data = geo.json()
                    addr = geo_data.get("address", {})
                    result["location"]["address"] = {
                        "city":     addr.get("city") or addr.get("town") or addr.get("village", "Unknown"),
                        "state":    addr.get("state", "Unknown"),
                        "country":  addr.get("country", "Unknown"),
                        "postcode": addr.get("postcode", "Unknown"),
                        "full":     geo_data.get("display_name", "Unknown")
                    }
                except:
                    pass
            else:
                result["location"] = {"location_found": False}
        else:
            result["location"] = {"location_found": False}

    except Exception as e:
        result["device"]["error"] = str(e)

    # Risk Score
    risk = 0
    if result["location"].get("location_found"): risk += 60
    if result["device"].get("make") != "Unknown": risk += 20
    if result["datetime"].get("taken") != "Unknown": risk += 20
    result["risk_score"] = min(100, risk)
    result["risk_level"] = (
        "CRITICAL" if risk >= 75 else
        "HIGH"     if risk >= 50 else
        "MEDIUM"   if risk >= 25 else
        "LOW"
    )

    return result
