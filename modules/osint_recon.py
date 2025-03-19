import requests
import shodan
import json
import subprocess
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from config.config import CONFIG
from .utils import log_event, store_result, save_output

def shodan_scan(target):
    api_key = CONFIG.get("SHODAN_API_KEY")
    if not api_key:
        log_event("Shodan API key not configured!", "error")
        return None
    
    try:
        api = shodan.Shodan(api_key)
        result = api.host(target)
        store_result("osint_recon", target, "shodan_scan")
        return result
    except shodan.APIError as e:
        log_event(f"Shodan API error: {e}", "error")
        return None

def hunter_email_lookup(domain):
    api_key = CONFIG.get("HUNTER_API_KEY")
    if not api_key:
        log_event("Hunter.io API key not configured!", "error")
        return None
    
    url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
    response = requests.get(url)
    if response.status_code == 200:
        store_result("osint_recon", domain, "hunter_email_lookup")
        return response.json()
    else:
        log_event(f"Hunter.io request failed: {response.text}", "error")
        return None

def run_wiggle_scan(target):
    try:
        result = subprocess.run(["wig", target, "-q"], capture_output=True, text=True)
        if result.returncode == 0:
            store_result("osint_recon", target, "wiggle_scan")
            return result.stdout.strip()
        else:
            log_event("Wiggle scan failed", "error")
            return None
    except Exception as e:
        log_event(f"Error running wiggle: {e}", "error")
        return None

def osint_recon(target):
    log_event(f"Starting OSINT recon on {target}")
    
    shodan_data = shodan_scan(target)
    hunter_data = hunter_email_lookup(target)
    wiggle_data = run_wiggle_scan(target)
    
    results = {
        "shodan": shodan_data,
        "hunter": hunter_data,
        "wiggle": wiggle_data,
    }
    
    save_output(f"osint_{target}.json", results)
    
    log_event(f"OSINT Recon completed. Results saved to output/osint_{target}.json")
    store_result ("osint_recon", target, "osint_recon")
    return results

def run():
    target = input("Enter target (domain, email, or IP address): ")
    osint_recon(target)

if __name__ == "__main__":
    run()
