import json
import os
from dotenv import load_dotenv

# Load environment variables from secrets.env
config_path = os.path.join(os.path.dirname(__file__), "secrets.env")
load_dotenv(config_path)

# Load JSON configuration
json_config_path = os.path.join(os.path.dirname(__file__), "config.json")
with open(json_config_path, "r") as f:
    CONFIG = json.load(f)

# Function to get configurations
def get_config(key, default=None):
    """Fetch configuration from JSON or environment variables."""
    return os.getenv(key, CONFIG.get(key, default))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG = {
    "DATABASE_PATH": os.path.join(BASE_DIR, "database", "phantomwatch.db"),
    "LOG_FILE": os.path.join(BASE_DIR, "logs", "phantomwatch.log"),
    "SIGMA_RULES_PATH": os.path.join(BASE_DIR, "config", "sigma_rules.yml"),
    "LOG_FILE_PATH": os.path.join(BASE_DIR, "logs", "system.log"),
    "THREAT_INTEL_REPORT": os.path.join(BASE_DIR, "output", "report.json"),
    "SIGMA_MATCHES_REPORT": os.path.join(BASE_DIR, "output", "sigma_matches.json"),
    "QUARANTINE_DIR": os.path.join(BASE_DIR, "quarantine"),
    "THREAT_INTEL_API_KEY": "your_api_key_here",
    "HOSTS_FILE": "C:\\Windows\\System32\\drivers\\etc\\hosts" if os.name == "nt" else "/etc/hosts",
    "WIFI_INTERFACE": "Wi-Fi" if os.name == "nt" else "wlan0"
}
