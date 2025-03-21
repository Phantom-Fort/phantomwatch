import os
import json
from dotenv import load_dotenv

dotenv_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config/secrets.env"))

# Load environment variables
load_dotenv(dotenv_path)

# Load JSON config
json_config_path = os.path.join(os.path.dirname(__file__), "config.json")
with open(json_config_path, "r") as f:
    json_config = json.load(f)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG = {
    **json_config,  # Merge JSON config into CONFIG
    "DATABASE_PATH": os.path.abspath(os.path.join(BASE_DIR, "..", "database", "phantomwatch.db")),
    "YARA_RULES_PATH": os.path.join(BASE_DIR, "..", "rules", "yara"),
    "ENV_PATH": os.path.join(BASE_DIR, "secrets.env"),
    "LOG_FILE": os.path.join(BASE_DIR, "..", "logs", "phantomwatch.log"),
    "ELASTICSEARCH_HOST": "http://localhost:9200",
    "MISP_URL": os.path.join(json_config.get("MISP_URL", "https://misp.local")),
    "ANYRUN_API_URL": "https://api.any.run/v1/submit",
    "VIRUSTOTAL_API_URL": "https://www.virustotal.com/api/v3",
    "HYBRIDANALYSIS_API_URL": "https://www.hybrid-analysis.com/api/v2/search/hash",
    "SIGMA_RULES_PATH": os.path.join(BASE_DIR, "rules", "sigma"),
    "LOG_FILE_PATH": os.path.join(BASE_DIR, "..", "logs", "phantomwatch.log"),
    "THREAT_INTEL_REPORT": os.path.join(BASE_DIR, "..", "output", "reports.json"),
    "SIGMA_MATCHES_REPORT": os.path.join(BASE_DIR, "..", "output", "sigma_matches.json"),
    "QUARANTINE_DIR": os.path.join(BASE_DIR, "..", "quarantine"),
    "FORENSIC REPORT": os.path.join(BASE_DIR, "..", "result", "forensics_report.json"),
    "MALWARE REPORT": os.path.join(BASE_DIR, "..", "result", "malware_analysis.json"),
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
