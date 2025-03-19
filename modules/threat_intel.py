import json
import requests
import os
import re
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
        VT_API_URL = CONFIG.get("VIRUSTOTAL_API_URL")
        VT_API_KEY = get_api_key("VIRUSTOTAL_API_KEY")
        if VT_API_KEY:
            try:
                vt_url = {VT_API_URL}/{ioc_type}/{value}
                headers = {"x-apikey": VT_API_KEY}
                response = session.get(vt_url, headers=headers)
                response.raise_for_status()
                results["VirusTotal"] = response.json()
                store_result(ioc_type, value, "VirusTotal", results["VirusTotal"])
            except requests.exceptions.RequestException as e:
                log_event(f"[ERROR] VirusTotal API request failed: {e}", "error")

        # MISP API
        MISP_API_KEY = get_api_key("MISP_API_KEY")
        MISP_URL = CONFIG.get("MISP_URL", "")
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

def detect_ioc(value):
    """Detects whether the given value is an IP, domain, or hash."""
    
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    domain_pattern = r"^(?!-)[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    hash_pattern = r"^[a-fA-F0-9]{32,64}$"  # MD5, SHA-1, SHA-256

    if re.match(ip_pattern, value):
        return "ip"
    elif re.match(domain_pattern, value):
        return "domain"
    elif re.match(hash_pattern, value):
        return "hash"
    else:
        return None

def run(ioc_value):
    """Runs threat intelligence lookup based on detected IOC type."""

    ioc_type = detect_ioc(ioc_value)
    if not ioc_type:
        print(f"[-] Invalid IOC format: {ioc_value}")
        sys.exit(1)

    print(f"[+] Detected {ioc_type}: {ioc_value}")
    
    try:
        results = fetch_threat_intel(ioc_type, ioc_value)
        save_output(results, CONFIG["THREAT_INTEL_REPORT"])
        print("[+] Threat intelligence lookup completed.")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m modules.threat_intel <IOC_value>")
        sys.exit(1)

    ioc_value = sys.argv[1]
    run(ioc_value)


