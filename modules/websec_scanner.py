import subprocess
import requests
import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.output_formatter import OutputFormatter
from config.config import CONFIG
from .utils import save_output, store_result

def is_wordpress(url):
    """Check if a website is running WordPress."""
    try:
        response = requests.get(url + "/wp-login.php", timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

def passive_recon(domain):
    """Perform passive reconnaissance using SecurityTrails API."""
    api_key = CONFIG.get("SECURITYTRAILS_API_KEY")
    if not api_key:
        OutputFormatter.log_message("SecurityTrails API key not found.", "error")
        return {}
    
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        return response.json() if response.status_code == 200 else {}
    except requests.RequestException as e:
        OutputFormatter.log_message(f"Error fetching SecurityTrails data: {e}", "error")
        return {}

def active_scan(target):
    """Run multiple web security scanners."""
    results = {}
    
    # Run Nikto
    try:
        nikto_output = subprocess.run(["nikto", "-h", target], capture_output=True, text=True)
        results["vulnerability_scan"] = nikto_output.stdout.strip()
    except Exception as e:
        OutputFormatter.log_message(f"Error running vulnerability scan: {e}", "error")
    
    # Run OWASP ZAP
    try:
        zap_output = subprocess.run(["zap-cli", "quick-scan", target], capture_output=True, text=True)
        results["security_scan"] = zap_output.stdout.strip()
    except Exception as e:
        OutputFormatter.log_message(f"Error running security scan: {e}", "error")
    
    # Run WPScan if WordPress detected
    if is_wordpress(target):
        try:
            wpscan_output = subprocess.run(["wpscan", "--url", target, "--enumerate", "vp"], capture_output=True, text=True)
            results["wordpress_scan"] = wpscan_output.stdout.strip()
        except Exception as e:
            OutputFormatter.log_message(f"Error running WordPress scan: {e}", "error")
    
    return results

def websec_scan(target):
    """Main function to perform web security scanning."""
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    
    OutputFormatter.log_message("Starting web security scan.")
    recon_data = passive_recon(domain)
    scan_results = active_scan(target)
    
    final_results = {"reconnaissance": recon_data, "scan_results": scan_results}
    save_output(final_results, "output/websec_scan.json")
    OutputFormatter.log_message("Web security scan completed.")
    store_result("websec_scanner", "Web security scan completed.", "websec_scan", "High")
    
    return final_results

def run(target_url):
    """Runs the web security scanner on the given URL."""
    
    print(f"[+] Scanning {target_url} for security vulnerabilities...")

    try:
        websec_scan(target_url)
        OutputFormatter.log_message(f"Web security scan completed for {target_url}.", "info")
    except Exception as e:
        OutputFormatter.log_message(f"Error during web security scan: {e}", "error")
        print(f"[-] Scan failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m modules.websec_scanner <target_url>")
        sys.exit(1)

    target_url = sys.argv[1]
    run(target_url)
