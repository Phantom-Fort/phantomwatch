import requests
import shodan
import json
import subprocess
import os
import sys
from loguru import logger

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from config.config import CONFIG
from .utils import store_result, save_output

logger.add("../logs/phantomwatch.log", rotation="10MB", level="INFO", format="{time} | {level} | {message}")

def log_message(message, msg_type="info"):
    """Logs messages using Loguru instead of print statements."""
    if msg_type == "success":
        logger.success(message)
    elif msg_type == "error":
        logger.error(message)
    elif msg_type == "warning":
        logger.warning(message)
    else:
        logger.info(message)

def shodan_scan(target):
    api_key = CONFIG.get("SHODAN_API_KEY")
    if not api_key:
        log_message("Shodan API key not configured!", "error")
        return None
    
    try:
        api = shodan.Shodan(api_key)
        result = api.host(target)
        store_result("osint_recon", target, "shodan_scan")
        return result
    except shodan.APIError as e:
        log_message(f"Shodan API error: {e}", "error")
        return None

def hunter_email_lookup(domain):
    api_key = CONFIG.get("HUNTER_API_KEY")
    if not api_key:
        log_message("Hunter.io API key not configured!", "error")
        return None
    
    url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
    response = requests.get(url)
    if response.status_code == 200:
        store_result("osint_recon", domain, "hunter_email_lookup")
        return response.json()
    else:
        log_message(f"Hunter.io request failed: {response.text}", "error")
        return None

def run_wiggle_scan(target):
    try:
        result = subprocess.run(["wig", target, "-q"], capture_output=True, text=True)
        if result.returncode == 0:
            store_result("osint_recon", target, "wiggle_scan")
            return result.stdout.strip()
        else:
            log_message("Wiggle scan failed", "error")
            return None
    except Exception as e:
        log_message(f"Error running wiggle: {e}", "error")
        return None

def osint_recon(target):
    log_message(f"Starting OSINT recon on {target}")
    
    shodan_data = shodan_scan(target)
    hunter_data = hunter_email_lookup(target)
    wiggle_data = run_wiggle_scan(target)
    
    results = {
        "shodan": shodan_data,
        "hunter": hunter_data,
        "wiggle": wiggle_data,
    }
    
    save_output(f"osint_{target}.json", results)
    
    log_message(f"OSINT Recon completed. Results saved to output/osint_{target}.json")
    store_result ("osint_recon", target, "osint_recon")
    return results

def run(target):
    """Runs OSINT reconnaissance on the given target."""
    
    if not target:
        print("[-] Error: No target provided.")
        return

    print(f"[+] Running OSINT reconnaissance on: {target}")

    try:
        results = osint_recon(target) or {}

        log_message(f"OSINT results for {target}: {json.dumps(results, indent=4)}", "info")
        store_result("osint_recon", target, results)
        save_output("osint_recon_results.json", results)

        print(json.dumps(results, indent=4))

    except Exception as e:
        print(f"[-] Error during OSINT reconnaissance: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m modules.osint_recon <target>")
        sys.exit(1)

    target = sys.argv[1]  # Get target from CLI
    run(target)

