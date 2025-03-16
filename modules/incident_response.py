import json
import requests
import os
import sys
import subprocess
import shutil
import psutil
import sqlite3
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from .utils import get_api_key, log_event, init_db, store_result, log_incident, fetch_threat_intel, save_output
from config.config import CONFIG  # Import config

# Database setup
init_db()

def block_ip(ip):
    try:
        if os.name == "nt":
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", "name=BlockIP", "dir=in", "action=block", "remoteip=" + ip], check=True)
        else:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        log_incident("Block IP", ip, "Success")
        store_result("incident_cases", {"action": "Block IP", "target": ip, "status": "Success", "timestamp": datetime.utcnow().isoformat()})
    except Exception as e:
        log_incident("Block IP", ip, f"Failed: {e}")

def block_domain(domain):
    try:
        with open(CONFIG["HOSTS_FILE"], "a") as f:
            f.write(f"127.0.0.1 {domain}\n")
        log_incident("Block Domain", domain, "Success")
        store_result("incident_cases", {"action": "Block Domain", "target": domain, "status": "Success", "timestamp": datetime.utcnow().isoformat()})
    except Exception as e:
        log_incident("Block Domain", domain, f"Failed: {e}")

def quarantine_file(file_path):
    try:
        os.makedirs(CONFIG["QUARANTINE_DIR"], exist_ok=True)
        shutil.move(file_path, CONFIG["QUARANTINE_DIR"])
        log_incident("Quarantine File", file_path, "Success")
        store_result("incident_cases", {"action": "Quarantine File", "target": file_path, "status": "Success", "timestamp": datetime.utcnow().isoformat()})
    except Exception as e:
        log_incident("Quarantine File", file_path, f"Failed: {e}")

def isolate_host():
    try:
        if os.name == "nt":
            subprocess.run(["netsh", "interface", "set", "interface", CONFIG["WIFI_INTERFACE"], "admin=disable"], check=True)
        else:
            subprocess.run(["nmcli", "radio", "wifi", "off"], check=True)
        log_incident("Isolate Host", "Local Machine", "Success")
        store_result("incident_cases", {"action": "Isolate Host", "target": "Local Machine", "status": "Success", "timestamp": datetime.utcnow().isoformat()})
    except Exception as e:
        log_incident("Isolate Host", "Local Machine", f"Failed: {e}")

def track_incident(case_id, action, status):
    conn = sqlite3.connect(CONFIG["DATABASE_PATH"])
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO incident_tracking (case_id, action, status, timestamp)
    VALUES (?, ?, ?, ?)
    """, (case_id, action, status, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def run_forensic_analysis():
    try:
        subprocess.run(["volatility", "-f", CONFIG["MEMORY_DUMP"], "imageinfo"], check=True)
        log_incident("Forensic Analysis", "Memory Dump", "Completed")
        store_result("incident_cases", {"action": "Forensic Analysis", "target": "Memory Dump", "status": "Completed", "timestamp": datetime.utcnow().isoformat()})
    except Exception as e:
        log_incident("Forensic Analysis", "Memory Dump", f"Failed: {e}")

if __name__ == "__main__":
    ioc_type = "ip"
    value = "1.1.1.1"
    results = fetch_threat_intel(ioc_type, value)
    save_output(results, "report.json")
    log_event("[*] Threat intelligence report saved.")
    track_incident("IR001", "Threat Intelligence Fetch", "Completed")
