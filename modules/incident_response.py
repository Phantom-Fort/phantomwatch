import json
import requests
import psutil
import os
import sys
import subprocess
import shutil
import sqlite3
from datetime import datetime
from loguru import logger

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from .utils import init_db, store_result, log_incident
from config.config import CONFIG  # Import config
from core.output_formatter import OutputFormatter

logger.add("logs/phantomwatch.log", rotation="10MB", level="INFO", format="{time} | {level} | {message}")
logger.add("logs/error.log", rotation="10MB", level="ERROR", format="{time} | {level} | {message}")


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

def run(log_file):
    """Executes incident response analysis on a log file."""
    
    if not log_file:
        print("[-] Error: Missing log file path.")
        return

    try:
        # Run Volatility against the log file
        result = subprocess.run(["volatility", "-f", log_file, "imageinfo"], check=True, capture_output=True, text=True)
        
        # Store and log results
        log_incident("Forensic Analysis", "Memory Dump", "Completed")
        store_result("incident_cases", {
            "action": "Forensic Analysis",
            "target": "Memory Dump",
            "status": "Completed",
            "timestamp": datetime.utcnow().isoformat(),
            "output": result.stdout  # Store output for reference
        })

        # Print stored result from the database
        conn = sqlite3.connect(CONFIG["DATABASE_PATH"])
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM incident_cases ORDER BY timestamp DESC LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        
        if row:
            formatter = OutputFormatter()
            formatted_output = formatter.format(row)
            print("Stored Result:", formatted_output)
        else:
            print("No results found in the database.")

    except FileNotFoundError:
        print("[-] Error: Volatility is not installed or not found in PATH.")
    except subprocess.CalledProcessError as e:
        log_incident("Forensic Analysis", "Memory Dump", f"Failed: {e}")
        print(f"[-] Command execution failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m modules.incident_response <log_file>")
        sys.exit(1)

    log_file = sys.argv[1]  # Get log file path from CLI
    run(log_file)
