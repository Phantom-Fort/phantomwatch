import subprocess
import requests
import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from config.config import CONFIG
from .utils import log_event, save_output

def is_wordpress(url):
    """Check if a website is running WordPress."""
    try:
        response = requests.get(url + "/wp-login.php", timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

def passive_recon(domain):
    """Perform passive reconnaissance using SecurityTrails API."""
    api_key = CONFIG.get("SECURITYTRAILS_API")
    if not api_key:
        log_event("SecurityTrails API key not found.", "error")
        return {}
    
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        return response.json() if response.status_code == 200 else {}
    except requests.RequestException as e:
        log_event(f"Error fetching SecurityTrails data: {e}", "error")
        return {}

def active_scan(target):
    """Run multiple web security scanners."""
    results = {}
    
    # Run Nikto
    try:
        nikto_output = subprocess.run(["nikto", "-h", target], capture_output=True, text=True)
        results["vulnerability_scan"] = nikto_output.stdout.strip()
    except Exception as e:
        log_event(f"Error running vulnerability scan: {e}", "error")
    
    # Run OWASP ZAP
    try:
        zap_output = subprocess.run(["zap-cli", "quick-scan", target], capture_output=True, text=True)
        results["security_scan"] = zap_output.stdout.strip()
    except Exception as e:
        log_event(f"Error running security scan: {e}", "error")
    
    # Run WPScan if WordPress detected
    if is_wordpress(target):
        try:
            wpscan_output = subprocess.run(["wpscan", "--url", target, "--enumerate", "vp"], capture_output=True, text=True)
            results["wordpress_scan"] = wpscan_output.stdout.strip()
        except Exception as e:
            log_event(f"Error running WordPress scan: {e}", "error")
    
    return results

def websec_scan(target):
    """Main function to perform web security scanning."""
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    
    log_event("Starting web security scan.")
    recon_data = passive_recon(domain)
    scan_results = active_scan(target)
    
    final_results = {"reconnaissance": recon_data, "scan_results": scan_results}
    save_output(final_results, "output/websec_scan.json")
    log_event("Web security scan completed.")
    
    return final_results

def run():
    target_url = "https://example.com"
    websec_scan(target_url)
    
if __name__ == "__main__":
    run()
