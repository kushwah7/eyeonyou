import requests
import re
import os

RAPIDAPI_KEY = os.getenv("RAPIDAPI_KEY", "")

def validate_plate(plate: str):
    """Validate Indian vehicle number plate format"""
    plate = plate.upper().replace(" ","").replace("-","")
    
    # Indian plate patterns
    patterns = [
        r'^[A-Z]{2}[0-9]{2}[A-Z]{1,2}[0-9]{1,4}$',  # Standard: GJ05AB1234
        r'^[A-Z]{2}[0-9]{2}[A-Z]{3}[0-9]{4}$',        # New BH series
        r'^[0-9]{2}BH[0-9]{4}[A-Z]{2}$',               # BH series
    ]
    
    for pattern in patterns:
        if re.match(pattern, plate):
            return True, plate
    return False, plate


def get_state_from_plate(plate: str):
    """Get state name from plate code"""
    plate = plate.upper()
    state_codes = {
        "AN": "Andaman & Nicobar", "AP": "Andhra Pradesh",
        "AR": "Arunachal Pradesh", "AS": "Assam",
        "BR": "Bihar", "CG": "Chhattisgarh",
        "CH": "Chandigarh", "DD": "Daman & Diu",
        "DL": "Delhi", "DN": "Dadra & Nagar Haveli",
        "GA": "Goa", "GJ": "Gujarat",
        "HP": "Himachal Pradesh", "HR": "Haryana",
        "JH": "Jharkhand", "JK": "Jammu & Kashmir",
        "KA": "Karnataka", "KL": "Kerala",
        "LA": "Ladakh", "LD": "Lakshadweep",
        "MH": "Maharashtra", "ML": "Meghalaya",
        "MN": "Manipur", "MP": "Madhya Pradesh",
        "MZ": "Mizoram", "NL": "Nagaland",
        "OD": "Odisha", "PB": "Punjab",
        "PD": "Puducherry", "PY": "Puducherry",
        "RJ": "Rajasthan", "SK": "Sikkim",
        "TN": "Tamil Nadu", "TR": "Tripura",
        "TS": "Telangana", "UK": "Uttarakhand",
        "UP": "Uttar Pradesh", "WB": "West Bengal",
    }
    code = plate[:2]
    return state_codes.get(code, "Unknown")


def get_rto_info(plate: str):
    """Get RTO office info from plate"""
    plate = plate.upper()
    state_code = plate[:2]
    rto_num = plate[2:4]

    state = get_state_from_plate(plate)

    return {
        "state_code":   state_code,
        "rto_number":   rto_num,
        "state":        state,
        "rto_office":   f"RTO {state_code}-{rto_num}",
        "rto_search_url": f"https://vahan.parivahan.gov.in/vahanservice/vahan/ui/statevalidation/validateBH.xhtml",
    }


def check_vehicle_rapidapi(plate: str):
    """Check vehicle details via RapidAPI"""
    try:
        # Try multiple RapidAPI vehicle endpoints
        headers = {
            "X-RapidAPI-Key": RAPIDAPI_KEY,
            "X-RapidAPI-Host": "rto-vehicle-information-verification-india.p.rapidapi.com"
        }

        r = requests.post(
            "https://rto-vehicle-information-verification-india.p.rapidapi.com/api/v1/rc/vehicleinfo",
            headers=headers,
            json={
                "reg_no": plate,
                "consent": "Y",
                "consent_text": "I hereby declare my consent agreement for fetching my information via AITAN Labs API"
            },
            timeout=15
        )

        if r.status_code == 200:
            data = r.json()
            result = data.get("result", data)

            return {
                "found":             True,
                "source":            "RapidAPI",
                "plate":             plate,
                "owner_name":        result.get("owner_name", ""),
                "vehicle_class":     result.get("vehicle_class", ""),
                "maker_model":       result.get("maker_model", ""),
                "maker_description": result.get("maker_description", ""),
                "body_type":         result.get("body_type", ""),
                "fuel_type":         result.get("fuel_type", ""),
                "color":             result.get("color", ""),
                "engine_no":         result.get("engine_no", "")[:6]+"***" if result.get("engine_no") else "",
                "chassis_no":        result.get("chassis_no", "")[:6]+"***" if result.get("chassis_no") else "",
                "registration_date": result.get("registration_date", ""),
                "registration_upto": result.get("registration_upto", ""),
                "insurance_upto":    result.get("insurance_upto", ""),
                "puc_upto":          result.get("puc_upto", ""),
                "fitness_upto":      result.get("fitness_upto", ""),
                "seating_capacity":  result.get("seating_capacity", ""),
                "gross_weight":      result.get("gross_vehicle_weight", ""),
                "wheelbase":         result.get("wheelbase", ""),
                "cubic_capacity":    result.get("cubic_capacity", ""),
                "cylinders":         result.get("no_of_cylinder", ""),
                "manufacturing_year":result.get("manufacturing_yr", ""),
                "norms_type":        result.get("norms_type", ""),
                "status":            result.get("vehicle_status", ""),
                "blacklist_status":  result.get("blacklist_status", ""),
                "challan_details":   result.get("challan_details", []),
                "financer":          result.get("financer", ""),
                "permit_type":       result.get("permit_type", ""),
                "permit_valid_upto": result.get("permit_valid_upto", ""),
                "tax_upto":          result.get("tax_upto", ""),
            }

    except Exception as e:
        return {"found": False, "error": str(e), "source": "RapidAPI"}

    return {"found": False, "source": "RapidAPI"}


def check_vehicle_vahan(plate: str):
    """Check vehicle via Vahan public API"""
    try:
        session = requests.Session()
        session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": "https://vahan.parivahan.gov.in",
            "Referer": "https://vahan.parivahan.gov.in/vahanservice/",
        }

        # Try Vahan API
        r = session.post(
            "https://vahan.parivahan.gov.in/vahanservice/vahan/api/validRC/vehicleRCdetails",
            json={"regNo": plate},
            timeout=10
        )

        if r.status_code == 200:
            data = r.json()
            if data:
                return {
                    "found": True,
                    "source": "Vahan",
                    "owner_name":        data.get("ownerName",""),
                    "vehicle_class":     data.get("vehicleClass",""),
                    "maker_model":       data.get("makerModel",""),
                    "fuel_type":         data.get("fuelType",""),
                    "color":             data.get("color",""),
                    "registration_date": data.get("registrationDate",""),
                    "registration_upto": data.get("regUpto",""),
                    "insurance_upto":    data.get("insuranceUpto",""),
                    "puc_upto":          data.get("pucUpto",""),
                    "fitness_upto":      data.get("fitnessUpto",""),
                    "engine_no":         str(data.get("engineNo",""))[:6]+"***",
                    "chassis_no":        str(data.get("chassisNo",""))[:6]+"***",
                    "manufacturing_year":data.get("manufacturingYear",""),
                    "seating_capacity":  data.get("seatingCapacity",""),
                    "status":            data.get("vehicleStatus",""),
                    "blacklist_status":  data.get("blacklistStatus",""),
                    "financer":          data.get("financer",""),
                    "tax_upto":          data.get("taxUpto",""),
                    "norms_type":        data.get("normsType",""),
                }

        # Try alternative Vahan endpoint
        r2 = session.get(
            f"https://vahan.parivahan.gov.in/vahanservice/vahan/api/validRC/vehicleRCdetails/{plate}",
            timeout=10
        )
        if r2.status_code == 200:
            data = r2.json()
            if data:
                return {"found": True, "source": "Vahan", **data}

    except Exception as e:
        pass

    return {
        "found": False,
        "source": "Vahan",
        "note": "Vahan requires manual verification"
    }


def check_insurance_status(plate: str):
    """Check insurance via IIB (Insurance Information Bureau)"""
    return {
        "check_url":   f"https://iib.gov.in/IBAS/faces/jsp/VI.xhtml",
        "plate":       plate,
        "note":        "Use IIB portal to verify insurance status",
        "iib_url":     "https://iib.gov.in/IBAS/faces/jsp/VI.xhtml",
        "parivahan_url": f"https://parivahan.gov.in/rcdlstatus/",
    }


def check_challan_status(plate: str):
    """Check traffic challan/fine status"""
    return {
        "echallan_url":    f"https://echallan.parivahan.gov.in/index/accused-challan",
        "plate":           plate,
        "note":            "Check pending challans on eChallan portal",
        "delhi_challan":   f"https://www.delhitrafficpolice.nic.in/check-online-services/",
        "mh_challan":      f"https://mahatrafficpolice.gov.in/",
        "up_challan":      f"https://uppolice.gov.in/",
    }


def get_vehicle_osint(plate: str):
    """Complete vehicle OSINT"""

    # Clean and validate
    plate = plate.upper().replace(" ","").replace("-","")
    is_valid, clean_plate = validate_plate(plate)

    result = {
        "plate":         clean_plate,
        "is_valid":      is_valid,
        "state_info":    get_rto_info(clean_plate),
        "vehicle_data":  {},
        "vahan_check":   {},
        "insurance":     {},
        "challan":       {},
        "manual_links":  {},
        "risk_score":    0,
        "risk_level":    "LOW"
    }

    if not is_valid:
        result["error"] = "Invalid plate format. Use format: GJ05AB1234"
        return result

    # RapidAPI check
    rapidapi_result = check_vehicle_rapidapi(clean_plate)
    result["vehicle_data"] = rapidapi_result

    # Vahan check
    result["vahan_check"] = check_vehicle_vahan(clean_plate)

    # Insurance check
    result["insurance"] = check_insurance_status(clean_plate)

    # Challan check
    result["challan"] = check_challan_status(clean_plate)

    # Manual verification links
    result["manual_links"] = {
        "Parivahan_RC_Status": "https://parivahan.gov.in/rcdlstatus/",
        "Vahan_Search":        "https://vahan.parivahan.gov.in/vahanservice/",
        "eChallan":            "https://echallan.parivahan.gov.in/index/accused-challan",
        "IIB_Insurance":       "https://iib.gov.in/IBAS/faces/jsp/VI.xhtml",
        "mParivahan_App":      "https://play.google.com/store/apps/details?id=com.nic.mParivahan",
        "PUCC_Check":          "https://puc.parivahan.gov.in/pucapp/",
    }

    # Risk Score
    risk = 0
    vd = result["vehicle_data"]
    if vd.get("blacklist_status") and "blacklist" in str(vd.get("blacklist_status","")).lower():
        risk += 50
    if vd.get("challan_details") and len(vd.get("challan_details",[])) > 0:
        risk += 30
    insurance = str(vd.get("insurance_upto",""))
    if insurance and insurance < str(__import__('datetime').datetime.now().date()):
        risk += 20

    result["risk_score"] = min(100, risk)
    result["risk_level"] = (
        "CRITICAL" if risk >= 75 else
        "HIGH"     if risk >= 50 else
        "MEDIUM"   if risk >= 25 else
        "LOW"
    )

    return result
