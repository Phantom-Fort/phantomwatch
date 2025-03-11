import os
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv(os.path.join(os.path.dirname(__file__), "secrets.env"))

# Load JSON config
json_config_path = os.path.join(os.path.dirname(__file__), "config.json")
with open(json_config_path, "r") as f:
    json_config = json.load(f)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG = {
    **json_config,  # Merge JSON config into CONFIG
    "DATABASE_PATH": os.path.abspath("database/phantomwatch.db"),
    "LOG_FILE": os.path.join(BASE_DIR, "..", "logs", "phantomwatch.log"),
    "SIGMA_RULES_PATH": os.path.join(BASE_DIR, "config", "sigma_rules.yml"),
    "LOG_FILE_PATH": os.path.join(BASE_DIR, "logs", "system.log"),
    "THREAT_INTEL_REPORT": os.path.join(BASE_DIR, "output", "report.json"),
    "SIGMA_MATCHES_REPORT": os.path.join(BASE_DIR, "output", "sigma_matches.json"),
    "QUARANTINE_DIR": os.path.join(BASE_DIR, "quarantine"),
    "THREAT_INTEL_API_KEY": os.getenv("THREAT_INTEL_API_KEY", "your_api_key_here"),
    "HOSTS_FILE": "C:\\Windows\\System32\\drivers\\etc\\hosts" if os.name == "nt" else "/etc/hosts",
    "WIFI_INTERFACE": "Wi-Fi" if os.name == "nt" else "wlan0"
}
