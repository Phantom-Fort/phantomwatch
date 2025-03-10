import json
import requests
import os
import sys
import yaml
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from .utils import get_api_key, log_event, init_db, store_result, store_sigma_match
from config.config import CONFIG  # Import config file

# Database Initialization
init_db()

def fetch_threat_intel(ioc_type, value):
    results = {}
    
    # VirusTotal API
    VT_API_KEY = get_api_key("VT_API_KEY")
    if VT_API_KEY:
        vt_url = f"https://www.virustotal.com/api/v3/{ioc_type}/{value}"
        headers = {"x-apikey": VT_API_KEY}
        
        try:
            response = requests.get(vt_url, headers=headers)
            response.raise_for_status()
            results["VirusTotal"] = response.json()
            store_result(ioc_type, value, "VirusTotal")
        except requests.exceptions.RequestException as e:
            log_event(f"[ERROR] VirusTotal API request failed: {e}")

    return results

def load_sigma_rules(rule_file):
    if not os.path.exists(rule_file):
        log_event(f"[ERROR] Sigma rule file not found: {rule_file}")
        return {"rules": []}

    try:
        with open(rule_file, "r") as f:
            rules = yaml.safe_load(f)
        return rules
    except yaml.YAMLError as e:
        log_event(f"[ERROR] Error parsing Sigma rules YAML: {e}")
        return {"rules": []}

def apply_sigma_rules(log_file, sigma_rules):
    if not os.path.exists(log_file):
        log_event(f"[ERROR] Log file not found: {log_file}")
        return []

    try:
        with open(log_file, "r") as f:
            logs = f.readlines()
    except Exception as e:
        log_event(f"[ERROR] Error reading log file: {e}")
        return []

    matches = []
    for rule in sigma_rules.get("rules", []):
        rule_name = rule.get("title", "Unknown Rule")
        description = rule.get("description", "No description available")
        detection_strings = rule.get("detection", {}).get("keywords", [])

        for log in logs:
            if any(keyword in log for keyword in detection_strings):
                match = {"rule_name": rule_name, "description": description, "log_entry": log.strip()}
                matches.append(match)
                store_sigma_match(rule_name, description, log.strip())

    return matches

def save_output(results, filename):
    try:
        with open(filename, "w") as f:
            json.dump(results, f, indent=4)
        log_event(f"[INFO] Output saved to {filename}")
    except Exception as e:
        log_event(f"[ERROR] Failed to save output: {e}")

if __name__ == "__main__":
    ioc_type = "ip"
    value = "1.1.1.1"

    # Fetch Threat Intelligence
    results = fetch_threat_intel(ioc_type, value)
    save_output(results, CONFIG["THREAT_INTEL_REPORT"])

    # Apply Sigma Rules
    sigma_rules = load_sigma_rules(CONFIG["SIGMA_RULES_PATH"])
    matches = apply_sigma_rules(CONFIG["LOG_FILE_PATH"], sigma_rules)
    save_output(matches, CONFIG["SIGMA_MATCHES_REPORT"])
