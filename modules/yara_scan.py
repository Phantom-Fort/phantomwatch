import yara
import os
import json
from datetime import datetime
from config.config import CONFIG

from .utils import log_event, init_db, store_result

# Initialize database
init_db()

# Get paths from config
YARA_RULES_DIR = CONFIG.get("SIGMA_RULES_PATH", "rules/yara/")
SAMPLE_FILE = CONFIG.get("SAMPLE_FILE", "samples/malware.exe")
SCAN_OUTPUT_FILE = CONFIG.get("THREAT_INTEL_REPORT", "output/yara_scan_results.json")

def load_yara_rules():
    """Load and compile all YARA rules from the directory."""
    if not os.path.exists(YARA_RULES_DIR):
        log_event("[ERROR] YARA rules directory not found!", "error")
        return None

    yara_rule_files = {
        file: os.path.join(YARA_RULES_DIR, file)
        for file in os.listdir(YARA_RULES_DIR)
        if file.endswith(".yar") or file.endswith(".yara")
    }

    if not yara_rule_files:
        log_event("[WARNING] No YARA rules found in the directory.", "warning")
        return None

    try:
        rules = yara.compile(filepaths=yara_rule_files)
        log_event(f"[INFO] Loaded {len(yara_rule_files)} YARA rules successfully.")
        return rules
    except yara.SyntaxError as e:
        log_event(f"[ERROR] Syntax error in YARA rules: {e}", "error")
        return None

def scan_file(file_path, rules):
    """Scan a file using compiled YARA rules and return results."""
    if not os.path.exists(file_path):
        log_event(f"[ERROR] File {file_path} not found!", "error")
        return []

    results = []
    try:
        matches = rules.match(file_path)
        for match in matches:
            result = {
                "file": file_path,
                "rule_name": match.rule,
                "tags": match.tags,
                "severity": "High" if "critical" in match.tags else "Medium",
                "timestamp": datetime.now().isoformat()
            }
            results.append(result)

            # Store result in the database
            store_result("yara_scan", result["file"], result["rule_name"])
            log_event(f"[MATCH] {match.rule} detected in {file_path} (Severity: {result['severity']})")
    except yara.YARAError as e:
        log_event(f"[ERROR] YARA scan failed for {file_path}: {e}", "error")

    return results

def save_results(results, output_file):
    """Save scan results to a JSON file."""
    try:
        with open(output_file, "w") as f:
            json.dump(results, f, indent=4)
        log_event(f"[INFO] Results saved to {output_file}")
    except Exception as e:
        log_event(f"[ERROR] Failed to save results: {e}", "error")

if __name__ == "__main__":
    yara_rules = load_yara_rules()
    if yara_rules:
        scan_results = scan_file(SAMPLE_FILE, yara_rules)
        if scan_results:
            save_results(scan_results, SCAN_OUTPUT_FILE)
        else:
            log_event("[INFO] No YARA matches found.")
