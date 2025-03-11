import subprocess
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

def scan_file_with_yara(file_path):
    """Scan a file using the YARA binary and return results."""
    if not os.path.exists(file_path):
        log_event(f"File {file_path} not found!", "error")
        return []

    # Run YARA as a subprocess
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

                # Store in database
                store_result("yara_scan", result_data["file"], result_data["rule_name"])
                log_event(f"[MATCH] {rule_name} detected in {file_path} (Severity: {result_data['severity']})")

            return scan_results

        elif result.returncode != 0:
            log_event(f"YARA scan failed: {result.stderr}", "error")
            return []

    except Exception as e:
        log_event(f"Failed to execute YARA: {e}", "error")
        return []

def save_results(results, output_file):
    """Save scan results to a JSON file."""
    try:
        with open(output_file, "w") as f:
            json.dump(results, f, indent=4)
        log_event(f"Results saved to {output_file}")
    except Exception as e:
        log_event(f"Failed to save results: {e}", "error")

if __name__ == "__main__":
    scan_results = scan_file_with_yara(SAMPLE_FILE)
    if scan_results:
        save_results(scan_results, SCAN_OUTPUT_FILE)
    else:
        log_event("No YARA matches found.")
