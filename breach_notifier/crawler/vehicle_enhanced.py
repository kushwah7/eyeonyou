import requests
import os

RAPIDAPI_KEY = os.getenv("RAPIDAPI_KEY","")

def check_stolen_vehicle(plate: str):
    """Check if vehicle is reported stolen"""
    return {
        "plate":      plate,
        "check_links": {
            "VAHAN_Stolen":   "https://vahan.parivahan.gov.in/vahanservice/",
            "Police_India":   "https://www.tracktheft.com/",
            "NCRB":          "https://www.ncrb.gov.in/",
        },
        "note": "Check manually on these portals for stolen vehicle status"
    }


def check_pucc_status(plate: str):
    """Check PUC/Pollution status"""
    return {
        "plate":      plate,
        "pucc_url":   f"https://puc.parivahan.gov.in/pucapp/",
        "check_url":  "https://parivahan.gov.in/rcdlstatus/",
        "note":       "Visit PUC portal to check pollution certificate status",
        "sms_check":  f"SMS VAHAN {plate} to 7738299899 for vehicle info"
    }


def check_challan_history(plate: str):
    """Get full challan history"""
    state_code = plate[:2].upper()

    state_challan_portals = {
        "GJ": "https://gujpol.nic.in/",
        "MH": "https://mahatrafficpolice.gov.in/",
        "DL": "https://www.delhitrafficpolice.nic.in/check-online-services/",
        "UP": "https://uppolice.gov.in/",
        "RJ": "https://traffic.rajpolice.gov.in/",
        "KA": "https://karnatakaone.gov.in/",
        "TN": "https://tnpolice.gov.in/",
        "AP": "https://www.appolice.gov.in/",
        "TS": "https://www.tspolice.gov.in/",
        "WB": "https://www.kolkatapolice.gov.in/",
    }

    return {
        "plate":          plate,
        "state":          state_code,
        "echallan_url":   f"https://echallan.parivahan.gov.in/index/accused-challan",
        "state_portal":   state_challan_portals.get(state_code, "https://echallan.parivahan.gov.in/"),
        "sms_check":      f"SMS VAHAN {plate} to 7738299899",
        "note":           "Check pending challans on eChallan portal"
    }


def check_owner_history(plate: str):
    """Check vehicle ownership history"""
    return {
        "plate":      plate,
        "check_url":  "https://vahan.parivahan.gov.in/vahanservice/",
        "note":       "Ownership history requires VAHAN portal access",
        "steps": [
            "Go to vahan.parivahan.gov.in",
            "Click 'Know Your Vehicle Details'",
            f"Enter plate number: {plate}",
            "Enter captcha",
            "View complete vehicle history"
        ]
    }


def check_route_permit(plate: str):
    """Check commercial vehicle route permit"""
    return {
        "plate":      plate,
        "permit_url": "https://parivahan.gov.in/parivahan/",
        "note":       "Route permit check available for commercial vehicles",
        "check_steps": [
            "Go to parivahan.gov.in",
            "Select 'Permit Services'",
            f"Search for vehicle: {plate}"
        ]
    }


def get_enhanced_vehicle_details(plate: str):
    """Get all enhanced vehicle details"""
    return {
        "plate":          plate,
        "stolen_check":   check_stolen_vehicle(plate),
        "pucc_status":    check_pucc_status(plate),
        "challan_history":check_challan_history(plate),
        "owner_history":  check_owner_history(plate),
        "route_permit":   check_route_permit(plate),
    }
