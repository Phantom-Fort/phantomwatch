import subprocess
import os
import json
import requests
import sys
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from config.config import CONFIG
from .utils import log_event, init_db, store_result, save_output

# Initialize database
init_db()

# Get paths from config
YARA_RULES_DIR = CONFIG.get("SIGMA_RULES_PATH", "rules/yara/")
SAMPLE_FILE = CONFIG.get("SAMPLE_FILE", "samples/malware.exe")
SCAN_OUTPUT_FILE = CONFIG.get("THREAT_INTEL_REPORT", "output/yara_scan_results.json")
HYBRID_ANALYSIS_API_KEY = CONFIG.get("HYBRIDANALYSIS_API_KEY", "")


def scan_file_with_yara(file_path):
    """Scan a file using the YARA binary and return results."""
    if not os.path.exists(file_path):
        log_event(f"File {file_path} not found!", "error")
        return []

    try:
        result = subprocess.run(
            ["yara", "-r", YARA_RULES_DIR, file_path],
            capture_output=True,
            text=True
        )

        if result.returncode == 0 and result.stdout:
            matches = result.stdout.strip().split("\n")
            scan_results = []
            for match in matches:
                rule_name = match.split(" ")[0]
                result_data = {
                    "file": file_path,
                    "rule_name": rule_name,
                    "timestamp": datetime.now().isoformat(),
                    "severity": "High" if "critical" in rule_name.lower() else "Medium"
                }
                scan_results.append(result_data)
                store_result("yara_scan", result_data["file"], result_data["rule_name"])
                log_event(f"[MATCH] {rule_name} detected in {file_path} (Severity: {result_data['severity']})")

            return scan_results
        
        elif result.returncode != 0:
            log_event(f"YARA scan failed: {result.stderr}", "error")
            return []

    except Exception as e:
        log_event(f"Failed to execute YARA: {e}", "error")
        return []


def fetch_hybrid_analysis(file_hash):
    """Fetch threat intelligence from HybridAnalysis API."""
    if not HYBRID_ANALYSIS_API_KEY:
        log_event("HybridAnalysis API key not set.", "error")
        return None

    url = "https://www.hybrid-analysis.com/api/v2/search/hash"
    headers = {
        "User-Agent": "Falcon Sandbox",
        "api-key": HYBRID_ANALYSIS_API_KEY
    }
    response = requests.get(url, headers=headers, params={"hash": file_hash})

    if response.status_code == 200:
        return response.json()
    else:
        log_event(f"HybridAnalysis API request failed: {response.status_code} - {response.text}", "error")
        return None


def run():
    scan_results = scan_file_with_yara(SAMPLE_FILE)
    if scan_results:
        save_output(scan_results, SCAN_OUTPUT_FILE)
        
        # Fetch threat intelligence from HybridAnalysis
        file_hash = "some_calculated_hash"  # Replace with actual file hash calculation
        intel_data = fetch_hybrid_analysis(file_hash)
        if intel_data:
            save_output(intel_data, "results/hybrid_analysis_results.json")
    else:
        log_event("No YARA matches found.")

if __name__ == "__main__":
    run()