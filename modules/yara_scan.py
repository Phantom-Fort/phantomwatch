import yara
import os
import json
import requests
import sys
import hashlib
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.output_formatter import OutputFormatter
from config.config import CONFIG
from .utils import init_db, store_result, save_output

# Initialize database
init_db()

# Get paths from config
YARA_RULES_DIR = CONFIG.get("YARA_RULES_PATH", "rules/yara/")
SCAN_OUTPUT_FILE = CONFIG.get("THREAT_INTEL_REPORT", "output/yara_scan_results.json")
HYBRID_ANALYSIS_API_KEY = CONFIG.get("HYBRIDANALYSIS_API_KEY", "")

def load_yara_rules():
    """Loads all YARA rules from the specified directory."""
    rule_files = {}
    
    # Collect all .yar or .yara files
    for root, _, files in os.walk(YARA_RULES_DIR):
        for file in files:
            if file.endswith(".yar") or file.endswith(".yara"):
                rule_path = os.path.join(root, file)
                rule_files[file] = rule_path

    if not rule_files:
        OutputFormatter.log_message("No YARA rules found!", "error")
        return None

    try:
        return yara.compile(filepaths=rule_files)
    except yara.SyntaxError as e:
        OutputFormatter.log_message(f"YARA syntax error: {e}", "error")
        return None
    except yara.Error as e:
        OutputFormatter.log_message(f"Failed to compile YARA rules: {e}", "error")
        return None


def scan_file_with_yara(file_path):
    """Scan a file using YARA rules and return results."""
    if not os.path.exists(file_path):
        OutputFormatter.log_message(f"File {file_path} not found!", "error")
        return []

    rules = load_yara_rules()
    if not rules:
        return []

    try:
        matches = rules.match(file_path)
        scan_results = []
        
        for match in matches:
            result_data = {
                "file": file_path,
                "rule_name": match.rule,
                "timestamp": datetime.now().isoformat(),
                "severity": "High" if "critical" in match.rule.lower() else "Medium"
            }
            scan_results.append(result_data)
            store_result("yara_scan", result_data["file"], result_data["rule_name"])
            OutputFormatter.log_message(f"[MATCH] {match.rule} detected in {file_path} (Severity: {result_data['severity']})")

        return scan_results

    except yara.Error as e:
        OutputFormatter.log_message(f"YARA scanning error: {e}", "error")
        return []


def fetch_hybrid_analysis(file_hash):
    """Fetch threat intelligence from HybridAnalysis API."""
    if not HYBRID_ANALYSIS_API_KEY:
        OutputFormatter.log_message("HybridAnalysis API key not set.", "error")
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
        OutputFormatter.log_message(f"HybridAnalysis API request failed: {response.status_code} - {response.text}", "error")
        return None


def calculate_file_hash(file_path):
    """Calculates SHA256 hash of a file."""
    try:
        with open(file_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        OutputFormatter.log_message(f"Error calculating file hash: {e}", "error")
        return None


def run(sample_file):
    """Runs YARA scan and fetches threat intelligence if necessary."""
    OutputFormatter.log_message(f"Starting YARA scan on: {sample_file}", "info")
    
    try:
        scan_results = scan_file_with_yara(sample_file)
        if scan_results:
            save_output(scan_results, SCAN_OUTPUT_FILE)
            OutputFormatter.log_message(f"YARA scan completed for {sample_file}.", "info")

            # Calculate file hash for threat intelligence
            file_hash = calculate_file_hash(sample_file)
            if file_hash:
                OutputFormatter.log_message(f"Fetching HybridAnalysis threat intelligence for hash: {file_hash}", "info")
                intel_data = fetch_hybrid_analysis(file_hash)
                if intel_data:
                    save_output(intel_data, "results/hybrid_analysis_results.json")
                    OutputFormatter.log_message(f"Threat intelligence stored for hash {file_hash}.", "info")
        else:
            OutputFormatter.log_message("No YARA matches found.", "warning")

    except Exception as e:
        OutputFormatter.log_message(f"Error running YARA scan: {e}", "error")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m modules.yara_scan <file_path>")
        sys.exit(1)

    sample_file = sys.argv[1]
    run(sample_file)
