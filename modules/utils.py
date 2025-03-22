import os
import sys
from datetime import datetime
import json
from loguru import logger
from dotenv import load_dotenv, set_key, dotenv_values
from core.output_formatter import OutputFormatter
import sqlite3
from config.config import CONFIG

logger.add("../logs/phantomwatch.log", rotation="10MB", level="INFO", format="{time} | {level} | {message}")

def log_message(message, msg_type="info"):
    """Logs messages using Loguru instead of print statements."""
    if msg_type == "success":
        logger.success(message)
    elif msg_type == "error":
        logger.error(message)
    elif msg_type == "warning":
        logger.warning(message)
    else:
        logger.info(message)

# Load environment variables
load_dotenv(CONFIG.get("ENV_PATH", None))

# Ensure necessary directories exist
os.makedirs(CONFIG.get("QUARANTINE_DIR", "quarantine"), exist_ok=True)
os.makedirs(os.path.dirname(CONFIG.get("LOG_FILE", "../logs/phantomwatch.log")), exist_ok=True)

logger.add(CONFIG.get("LOG_FILE", "../logs/phantomwatch.log"), rotation="10MB", level="INFO", format="{time} - {level} - {message}")

def log_incident(action, target, status):
    """Log an incident response action."""
    conn = sqlite3.connect(CONFIG.get("DATABASE_PATH", "phantomwatch.db"))
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO incident_response (action, target, status, timestamp) VALUES (?, ?, ?, datetime('now'))",
        (action, target, status)
    )
    conn.commit()
    conn.close()
    log_message(f"[*] Incident logged: {action} on {target} (Status: {status})", "info")

def fetch_threat_intel(ioc_type, value):
    """Fetch threat intelligence from the database."""
    conn = sqlite3.connect(CONFIG.get("DATABASE_PATH", "phantomwatch.db"))
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threat_intel WHERE type=? AND indicator=?", (ioc_type, value))
    result = cursor.fetchall()
    conn.close()
    return result

def save_output(data, file_path):
    if isinstance(data, list):  
        data = {"results": data}  # Wrap list in a dictionary for JSON compatibility
    with open(file_path, "w") as file:
        json.dump(data, file, indent=4)
    log_message(f"[*] Output saved to {file_path}")

def load_config():
    """Load non-sensitive configuration settings from config.json."""
    config_path = os.path.join(os.path.dirname(__file__), "config", "config.json")
    if not os.path.exists(config_path):
        log_message("[!] Configuration file missing!", "error")
        return {}

    with open(config_path, "r") as config_file:
        return json.load(config_file)

def save_config(updated_config):
    """Save the updated configuration to config.json."""
    config_path = os.path.join(os.path.dirname(__file__), "config", "config.json")
    with open(config_path, "w") as config_file:
        json.dump(updated_config, config_file, indent=4)
    log_message("[*] Configuration updated successfully.", "info")

def set_api_key(service, api_key):
    """Sets an API key in the .env file."""
    env_path = CONFIG.get("env_path", os.path.join(os.path.dirname(__file__), "..config/secrets.env"))
    
    set_key(env_path, service.upper(), api_key)
    OutputFormatter.print_message(f"[+] API key for {service.upper()} set successfully.", "success")
    log_message(f"API key for {service.upper()} updated.", "info")

# Load secrets.env from the config directory
dotenv_path = os.path.join(os.path.dirname(__file__), "../config/secrets.env")
load_dotenv(dotenv_path)  # Ensures environment variables are loaded

def get_api_key(service_names, dotenv_path="config/secrets.env"):
    """Retrieve API keys securely from environment variables or secrets.env."""
    
    # Load API keys from the secrets.env file
    env_config = dotenv_values(dotenv_path)  # Read .env as dictionary

    # Ensure service_names is a list
    if isinstance(service_names, str):  
        service_names = [service_names]  

    api_keys = {}

    for service_name in service_names:
        if not isinstance(service_name, str):  
            log_message(f"[!] Invalid API key format for: {service_name}", "error")
            continue

        env_var = f"{service_name.upper()}_API_KEY"

        # Try getting from environment variables first
        key = os.getenv(env_var)

        # If not found, try getting from secrets.env
        if not key:
            key = env_config.get(env_var)

        if not key:
            log_message(f"[!] API key for {service_name} is missing!", "error")
        else:
            api_keys[service_name] = key

    return api_keys


def store_sigma_match(rule_name, description, log_entry, filename="sigma_matches.json"):
    """Stores Sigma match details in a JSON file and logs the event."""
    match = {
        "rule_name": rule_name,
        "description": description,
        "log_entry": log_entry
    }
    
    # Check if file exists and read existing data
    if os.path.exists(filename):
        with open(filename, "r") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = []
    else:
        data = []

    # Append new match
    data.append(match)

    # Write back to file
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

    # Log the event
    log_message(f"[*] Sigma match stored: Rule - {rule_name}, Description - {description}", "info")


def init_db():
    """Initialize the database if it doesn’t exist."""
    conn = sqlite3.connect(CONFIG["DATABASE_PATH"])
    cursor = conn.cursor()

    # Creating required tables
    tables = {
        "threat_intel": '''CREATE TABLE IF NOT EXISTS threat_intel (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            ioc_type TEXT, value TEXT, source TEXT, timestamp TEXT)''',

        "siem_logs": '''CREATE TABLE IF NOT EXISTS siem_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT, log_data TEXT, source TEXT, timestamp TEXT)''',

        "incident_response": '''CREATE TABLE IF NOT EXISTS incident_response (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                action TEXT, target TEXT, status TEXT, timestamp TEXT)''',

        "yara_scan": '''CREATE TABLE IF NOT EXISTS yara_scan (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        file TEXT, rule_name TEXT, severity TEXT, timestamp TEXT)''',

        "sigma_rules": '''CREATE TABLE IF NOT EXISTS sigma_rules (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        log TEXT, rule_name TEXT, severity TEXT, timestamp TEXT)''',

        "exploit_finder": '''CREATE TABLE IF NOT EXISTS exploit_finder (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        log TEXT, rule_name TEXT, severity TEXT, timestamp TEXT)''',

        "forensic_analysis": '''CREATE TABLE IF NOT EXISTS forensic_analysis (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        log TEXT, rule_name TEXT, severity TEXT, timestamp TEXT)''',

        "malware_analysis": '''CREATE TABLE IF NOT EXISTS malware_analysis (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        log TEXT, rule_name TEXT, severity TEXT, timestamp TEXT)''',

        "network_scanner": '''CREATE TABLE IF NOT EXISTS network_scanner (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        log TEXT, rule_name TEXT, severity TEXT, timestamp TEXT)''',

        "osint_recon": '''CREATE TABLE IF NOT EXISTS osint_recon (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        log TEXT, rule_name TEXT, severity TEXT, timestamp TEXT)''',

        "websec_scanner": '''CREATE TABLE IF NOT EXISTS websec_scanner (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        log TEXT, rule_name TEXT, severity TEXT, timestamp TEXT)''',

        "incident_tracking": '''CREATE TABLE IF NOT EXISTS incident_tracking (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        incident_id TEXT, status TEXT, timestamp TEXT)'''
    }
    for table, query in tables.items():
        cursor.execute(query)

    conn.commit()
    conn.close()
    log_message("Database initialized successfully.", "info")

def store_result(table, log, rule_name, severity="Medium"):
    """Store scan results in the database."""
    conn = sqlite3.connect(CONFIG["DATABASE_PATH"])
    cursor = conn.cursor()
    cursor.execute(
        f"INSERT INTO {table} (log, rule_name, severity, timestamp) VALUES (?, ?, ?, datetime('now'))",
        (log, rule_name, severity)
    )
    conn.commit()
    conn.close()
    log_message(f"[*] Stored result in {table}: {rule_name} -> {log} (Severity: {severity})", "info")

def store_siem_results(table_name, data):
    conn = sqlite3.connect(CONFIG["DATABASE_PATH"])
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM {table_name}")  # Keep only the latest results
    for entry in data:
        cursor.execute(f"INSERT INTO {table_name} (timestamp, data) VALUES (?, ?)",
                       (datetime.now(), json.dumps(entry)))
    conn.commit()
    conn.close()

# Retrieve results by command
def get_saved_results(table_name):
    conn = sqlite3.connect(CONFIG["DATABASE_PATH"])
    cursor = conn.cursor()
    query = f"SELECT * FROM {table_name} ORDER BY timestamp DESC LIMIT 1"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return results

def check_requirements():
    """Ensure all necessary configurations are in place before running the modules."""
    required_keys = ["VT", "MISP", "OTX"]
    missing_keys = [key for key in required_keys if not get_api_key(key)]

    if missing_keys:
        log_message(f"[!] Missing API keys: {', '.join(missing_keys)}", "error")
        exit(1)

    if not os.path.exists(CONFIG["DATABASE_PATH"]):
        log_message("[!] Database not found. Initializing...", "warning")
        init_db()

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="PhantomWatch Utility Script")
    parser.add_argument("--set-api", nargs=2, metavar=("SERVICE", "API_KEY"), help="Set API key for a service")
    args = parser.parse_args()

    if args.set_api:
        service_name, api_key = args.set_api
        set_api_key(service_name, api_key)
    else:
        check_requirements()
        log_message("[*] All checks passed. PhantomWatch is ready to run.", "info")