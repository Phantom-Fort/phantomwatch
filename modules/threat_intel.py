import json
import requests
import os
import sys
from datetime import datetime
from OTXv2 import OTXv2, IndicatorTypes

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from .utils import get_api_key, log_event, init_db, store_result, save_output
from config.config import CONFIG  # Import config file

# Database setup
init_db()

def fetch_threat_intel(ioc_type, value):
    results = {}
    
    with requests.Session() as session:  # Optimize network calls
        # VirusTotal API
        VT_API_KEY = get_api_key("VIRUSTOTAL_API_KEY")
        if VT_API_KEY:
            try:
                vt_url = f"https://www.virustotal.com/api/v3/{ioc_type}/{value}"
                headers = {"x-apikey": VT_API_KEY}
                response = session.get(vt_url, headers=headers)
                response.raise_for_status()
                results["VirusTotal"] = response.json()
                store_result(ioc_type, value, "VirusTotal", results["VirusTotal"])
            except requests.exceptions.RequestException as e:
                log_event(f"[ERROR] VirusTotal API request failed: {e}")

        # MISP API
        MISP_API_KEY = get_api_key("MISP_API_KEY")
        MISP_URL = get_api_key("MISP_URL")
        if MISP_API_KEY and MISP_URL:
            try:
                misp_url = f"{MISP_URL}/events/restSearch/json"
                headers = {"Authorization": MISP_API_KEY, "Accept": "application/json"}
                response = session.post(misp_url, json={"value": value}, headers=headers)
                response.raise_for_status()
                results["MISP"] = response.json()
                store_result(ioc_type, value, "MISP", results["MISP"])
            except requests.exceptions.RequestException as e:
                log_event(f"[ERROR] MISP API request failed: {e}")

        # OTX API
        OTX_API_KEY = get_api_key("OTX_API_KEY")
        if OTX_API_KEY:
            try:
                otx = OTXv2(OTX_API_KEY)
                if ioc_type.upper() == "DOMAIN":
                    otx_results = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, value)
                elif ioc_type.upper() == "IP":
                    otx_results = otx.get_indicator_details_full(IndicatorTypes.IPv4, value)
                elif ioc_type.upper() == "HASH":
                    otx_results = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_MD5, value)
                else:
                    log_event(f"[ERROR] Unsupported IOC type: {ioc_type}")
                    return results

                results["OTX"] = otx_results
                store_result(ioc_type, value, "OTX", results["OTX"])
            except Exception as e:
                log_event(f"[ERROR] OTX API query failed: {e}")

        return results

def run():
    ioc_type = "ip", "domain", "hash"
    value = "1.1.1.1", "example.com", "hash_value"

    results = fetch_threat_intel(ioc_type, value)
    save_output(results, CONFIG["THREAT_INTEL_REPORT"])

if __name__ == "__main__":
    run()
