import os
import json
from dotenv import load_dotenv

# Determine installation directory
INSTALL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Load environment variables
dotenv_path = os.path.join(INSTALL_DIR, "config", "secrets.env")
load_dotenv(dotenv_path)

# Load JSON config
json_config_path = os.path.join(INSTALL_DIR, "config", "config.json")
with open(json_config_path, "r") as f:
    json_config = json.load(f)

# Ensure required directories exist in the installation directory
REQUIRED_DIRS = ["database", "logs", "rules", "output", "result", "quarantine"]

for directory in REQUIRED_DIRS:
    full_path = os.path.join(INSTALL_DIR, directory)
    os.makedirs(full_path, exist_ok=True)  # Create if not exists

# Fix permissions (optional, ensures access)
for directory in REQUIRED_DIRS:
    full_path = os.path.join(INSTALL_DIR, directory)
    try:
        os.chmod(full_path, 0o755)  # Read/Write/Execute for owner, Read/Execute for others
    except PermissionError:
        print(f"Warning: Unable to set permissions for {full_path}. You may need sudo.")

# Config Dictionary
CONFIG = {
    **json_config,  # Merge JSON config into CONFIG
    "DATABASE_PATH": os.path.join(INSTALL_DIR, "database", "phantomwatch.db"),
    "YARA_RULES_PATH": os.path.join(INSTALL_DIR, "rules", "yara"),
    "ENV_PATH": os.path.join(INSTALL_DIR, "secrets.env"),
    "LOG_FILE": os.path.join(INSTALL_DIR, "logs", "phantomwatch.log"),
    "ELASTICSEARCH_HOST": "http://localhost:9200",
    "MISP_URL": json_config.get("MISP_URL", "https://misp.local"),
    "ANYRUN_API_URL": "https://api.any.run/v1/submit",
    "VIRUSTOTAL_API_URL": "https://www.virustotal.com/api/v3",
    "HYBRIDANALYSIS_API_URL": "https://www.hybrid-analysis.com/api/v2/search/hash",
    "SIGMA_RULES_PATH": os.path.join(INSTALL_DIR, "rules", "sigma"),
    "LOG_FILE_PATH": os.path.join(INSTALL_DIR, "logs", "phantomwatch.log"),
    "THREAT_INTEL_REPORT": os.path.join(INSTALL_DIR, "output", "reports.json"),
    "SIGMA_MATCHES_REPORT": os.path.join(INSTALL_DIR, "output", "sigma_matches.json"),
    "QUARANTINE_DIR": os.path.join(INSTALL_DIR, "quarantine"),
    "FORENSIC_REPORT": os.path.join(INSTALL_DIR, "result", "forensics_report.json"),
    "MALWARE_REPORT": os.path.join(INSTALL_DIR, "result", "malware_analysis.json"),
    "HYBRIDANALYSIS_API_KEY": os.getenv("HYBRIDANALYSIS", "your_api_key_here"),
    "ANYRUN_API_KEY": os.getenv("ANYRUN", "your_api_key_here"),
    "SHODAN_API_KEY": os.getenv("SHODAN", "your_api_key_here"),
    "SECURITYTRAILS_API_KEY": os.getenv("SECURITYTRAILS", "your_api_key_here"),
    "HUNTER_API_KEY": os.getenv("HUNTER", "your_api_key_here"),
    "MISP_API_KEY": os.getenv("MISP", "your_api_key_here"),
    "OTX_API_KEY": os.getenv("OTX", "your_api_key_here"),
    "VIRUSTOTAL_API_KEY": os.getenv("VIRUSTOTAL", "your_api_key_here"),
    "HOSTS_FILE": "C:\\Windows\\System32\\drivers\\etc\\hosts" if os.name == "nt" else "/etc/hosts",
    "WIFI_INTERFACE": "Wi-Fi" if os.name == "nt" else "wlan0"
}
