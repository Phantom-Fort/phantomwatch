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
    "DATABASE_PATH": os.path.abspath(os.path.join(BASE_DIR, "..", "database", "phantomwatch.db")),
    "LOG_FILE": os.path.join(BASE_DIR, "..", "logs", "phantomwatch.log"),
    "SIGMA_RULES_PATH": os.path.join(BASE_DIR, "sigma_rules.yml"),
    "LOG_FILE_PATH": os.path.join(BASE_DIR, "..", "logs", "phantomwatch.log"),
    "THREAT_INTEL_REPORT": os.path.join(BASE_DIR, "..", "output", "report.json"),
    "SIGMA_MATCHES_REPORT": os.path.join(BASE_DIR, "..", "output", "sigma_matches.json"),
    "QUARANTINE_DIR": os.path.join(BASE_DIR, "..", "quarantine"),
    "DISK_IMAGE": os.path.join(BASE_DIR, "..", "samples", "disk_image.dd"),
    "MEMORY_DUMP": os.path.join(BASE_DIR, "..", "samples", "memory.dmp"),
    "FORENSIC REPORT": os.path.join(BASE_DIR, "..", "result", "forensics_report.json"),
    "MALWARE_SAMPLE": os.path.join(BASE_DIR, "..", "samples", "malware.exe"),
    "MALWARE REPORT": os.path.join(BASE_DIR, "..", "result", "malware_analysis.json"),
    "HYBRIDANALYSIS_API_KEY": os.getenv("THREAT_INTEL_API_KEY", "your_api_key_here"),
    "ANYRUN_API_KEY": os.getenv("ANYRUN_API_KEY", "your_api_key_here"),
    "SHODAN_API_KEY": os.getenv("SHODAN_API_KEY", "your_api_key_here"),
    "SECURITYTRAILS_API_KEY": os.getenv("SECURITYTRAILS_API_KEY", "your_api_key_here"),
    "HUNTER_API_KEY": os.getenv("HUNTER_API_KEY", "your_api_key_here"),
    "MISP_API_KEY": os.getenv("MISP_API_KEY", "your_api_key_here"),
    "VIRUSTOTAL_API_KEY": os.getenv("VIRUSTOTAL_API_KEY", "your_api_key_here"),
    "THREAT_INTEL_API_KEY": os.getenv("THREAT_INTEL_API_KEY", "your_api_key_here"),
    "HOSTS_FILE": "C:\\Windows\\System32\\drivers\\etc\\hosts" if os.name == "nt" else "/etc/hosts",
    "WIFI_INTERFACE": "Wi-Fi" if os.name == "nt" else "wlan0"
}
