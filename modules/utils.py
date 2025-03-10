import os
import json
from loguru import logger, logging
import sqlite3
from dotenv import load_dotenv
from config import get_config, CONFIG

# Load environment variables
load_dotenv("config/secrets.env")

# Ensure necessary directories exist
os.makedirs(CONFIG["QUARANTINE_DIR"], exist_ok=True)
os.makedirs(os.path.dirname(CONFIG["LOG_FILE"]), exist_ok=True)

# Logging Configuration
logging.basicConfig(
    filename=CONFIG["LOG_FILE"],
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def log_event(message, level="info"):
    """Log events to the log file."""
    level_map = {
        "info": logging.info,
        "warning": logging.warning,
        "error": logging.error
    }
    level_map.get(level, logging.info)(message)
    print(f"[*] {message}")

def load_config():
    """Load non-sensitive configuration settings from config.json."""
    config_path = os.path.join(os.path.dirname(__file__), "config", "config.json")
    if not os.path.exists(config_path):
        log_event("[!] Configuration file missing!", "error")
        return {}

    with open(config_path, "r") as config_file:
        return json.load(config_file)

def save_config(updated_config):
    """Save the updated configuration to config.json."""
    config_path = os.path.join(os.path.dirname(__file__), "config", "config.json")
    with open(config_path, "w") as config_file:
        json.dump(updated_config, config_file, indent=4)
    log_event("[*] Configuration updated successfully.")

def set_api_key(service_name, api_key):
    """Set and save API keys for different services in config.json."""
    config = load_config()
    config[f"{service_name.upper()}_API_KEY"] = api_key
    save_config(config)
    log_event(f"[*] API key for {service_name} has been updated.")

def get_api_key(service_name):
    """Retrieve API keys securely from environment variables or config.json."""
    config = load_config()
    api_key = os.getenv(f"{service_name.upper()}_API_KEY") or config.get(f"{service_name.upper()}_API_KEY")
    if not api_key:
        log_event(f"[!] API key for {service_name} is missing!", "error")
    return api_key

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
                        log TEXT, rule_name TEXT, severity TEXT, timestamp TEXT)'''
    }

    for table, query in tables.items():
        cursor.execute(query)

    conn.commit()
    conn.close()
    log_event("[*] Database initialized successfully.")

def store_result(table, file, rule_name, severity="Medium"):
    """Store scan results in the database."""
    conn = sqlite3.connect(CONFIG["DATABASE_PATH"])
    cursor = conn.cursor()
    cursor.execute(
        f"INSERT INTO {table} (file, rule_name, severity, timestamp) VALUES (?, ?, ?, datetime('now'))",
        (file, rule_name, severity)
    )
    conn.commit()
    conn.close()
    log_event(f"[*] Stored result in {table}: {rule_name} -> {file} (Severity: {severity})")

def check_requirements():
    """Ensure all necessary configurations are in place before running the modules."""
    required_keys = ["VT", "MISP", "OTX"]
    missing_keys = [key for key in required_keys if not get_api_key(key)]

    if missing_keys:
        log_event(f"[!] Missing API keys: {', '.join(missing_keys)}", "error")
        exit(1)

    if not os.path.exists(CONFIG["DATABASE_PATH"]):
        log_event("[!] Database not found. Initializing...", "warning")
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
        log_event("[*] All checks passed. PhantomWatch is ready to run.")
