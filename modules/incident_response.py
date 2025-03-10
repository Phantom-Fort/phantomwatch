import json
import requests
import os
import subprocess
import shutil
import psutil
from datetime import datetime
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
    except Exception as e:
        log_incident("Block IP", ip, f"Failed: {e}")

def block_domain(domain):
    try:
        with open(CONFIG["HOSTS_FILE"], "a") as f:
            f.write(f"127.0.0.1 {domain}\n")
        log_incident("Block Domain", domain, "Success")
    except Exception as e:
        log_incident("Block Domain", domain, f"Failed: {e}")

def quarantine_file(file_path):
    try:
        os.makedirs(CONFIG["QUARANTINE_DIR"], exist_ok=True)
        shutil.move(file_path, CONFIG["QUARANTINE_DIR"])
        log_incident("Quarantine File", file_path, "Success")
    except Exception as e:
        log_incident("Quarantine File", file_path, f"Failed: {e}")

def isolate_host():
    try:
        if os.name == "nt":
            subprocess.run(["netsh", "interface", "set", "interface", CONFIG["WIFI_INTERFACE"], "admin=disable"], check=True)
        else:
            subprocess.run(["nmcli", "radio", "wifi", "off"], check=True)
        log_incident("Isolate Host", "Local Machine", "Success")
    except Exception as e:
        log_incident("Isolate Host", "Local Machine", f"Failed: {e}")

if __name__ == "__main__":
    ioc_type = "ip"
    value = "1.1.1.1"
    results = fetch_threat_intel(ioc_type, value)
    save_output(results, "report.json")
    log_event("[*] Threat intelligence report saved.")