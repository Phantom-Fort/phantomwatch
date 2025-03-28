import json
import requests
import sqlite3
import os
import sys
import yaml
from elasticsearch import Elasticsearch
from sigma.parser.collection import SigmaCollectionParser
from sigma.backends.elasticsearch import LuceneBackend
from sigma.rule import SigmaRule
from sigma.pipelines.elasticsearch import ecs_windows
from datetime import datetime
from loguru import logger

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from .utils import init_db, store_siem_results, save_output, store_result
from config.config import CONFIG
from core.output_formatter import OutputFormatter

logger.add("logs/phantomwatch.log", rotation="10MB", level="INFO", format="{time} | {level} | {message}")
logger.add("logs/error.log", rotation="10MB", level="ERROR", format="{time} | {level} | {message}")

def log_message(message, msg_type="info"):
    """Logs messages using OutputFormatter instead of print statements."""
    OutputFormatter.log_message(message, msg_type)

# Initialize Database
init_db()

# Elasticsearch Configuration
ELASTICSEARCH_HOST = CONFIG.get("ELASTICSEARCH_HOST", "http://localhost:9200")
ELASTICSEARCH_API_KEY = CONFIG.get("ELASTICSEARCH_API_KEY", "")
INDEX_NAME = "logs-*"
SIGMA_RULES_FILE = CONFIG["SIGMA_RULES_PATH"]

# Initialize Elasticsearch client with API key
es = Elasticsearch(
    [ELASTICSEARCH_HOST],
    api_key=ELASTICSEARCH_API_KEY
)

# Load Sigma rules
def load_sigma_rules(rule_file):
    if not os.path.exists(rule_file):
        log_message(f"[ERROR] Sigma rule file not found: {rule_file}", "error")
        return []
    try:
        with open(rule_file, "r") as f:
            parser = SigmaCollectionParser(f.read(), SigmaRule())
            backend = LuceneBackend(SigmaRule())
            return [backend.convert(rule) for rule in parser.rules]
    except yaml.YAMLError as e:
        log_message(f"[ERROR] Error parsing Sigma rules YAML: {e}", "error")
        return []

# Search logs in Elasticsearch using Sigma rules
def search_logs_with_sigma():
    sigma_queries = load_sigma_rules(SIGMA_RULES_FILE)
    alerts = []
    for query in sigma_queries:
        response = es.search(index=INDEX_NAME, query={"query_string": {"query": query}})
        if response["hits"]["total"]["value"] > 0:
            alerts.extend(response["hits"]["hits"])
    
    # Store only the last successful execution result
    store_siem_results('siem_alerts', alerts)
    
    # Output results to a file
    save_output("siem_alerts.json", alerts)
    
    return alerts

# Correlate events from threat intelligence and incident response
def correlate_events():
    conn = sqlite3.connect(CONFIG["DATABASE_PATH"])
    cursor = conn.cursor()
    
    query = """
    SELECT ioc_type, value, source, timestamp FROM threat_intel
    WHERE timestamp >= datetime('now', '-7 days')
    """
    cursor.execute(query)
    intel_data = cursor.fetchall()
    
    query = """
    SELECT action, target, status, timestamp FROM incident_response
    WHERE timestamp >= datetime('now', '-7 days')
    """
    cursor.execute(query)
    incident_data = cursor.fetchall()
    
    correlation_results = []
    
    for intel in intel_data:
        ioc_type, value, source, intel_time = intel
        for incident in incident_data:
            action, target, status, incident_time = incident
            if value == target:
                correlation_results.append({
                    "ioc_type": ioc_type,
                    "value": value,
                    "source": source,
                    "intel_time": intel_time,
                    "action": action,
                    "status": status,
                    "incident_time": incident_time
                })
    
    # Store only the last successful correlation results
    store_siem_results('correlation_results', correlation_results)
    
    # Output results to a file
    save_output("correlation_results.json", correlation_results)
    
    log_message(f"[INFO] Correlated {len(correlation_results)} events.", "info")
    return correlation_results

# Main execution function
def analyze_siem_logs():
    try:
        alerts = search_logs_with_sigma()
        correlation_results = correlate_events()
        
        if alerts or correlation_results:
            OutputFormatter.print_message("[ALERT] Potential Threats Detected!", "warning")
            OutputFormatter.print_json({"alerts": alerts, "correlations": correlation_results})
        else:
            OutputFormatter.print_message("[INFO] No threats detected in logs.", "info")
    except Exception as e:
        log_message(f"[ERROR] Log analysis failed {str(e)}", "error")

def run(log_file):
    """Runs SIEM log analysis on the given log file."""
    
    if not log_file:
        OutputFormatter.print_message("[-] Error: No SIEM log file provided.", "error")
        return

    OutputFormatter.print_message(f"[+] Analyzing SIEM logs from: {log_file}", "info")

    try:
        analyze_siem_logs()
        log_message(f"SIEM log analysis completed for {log_file}", "info")
        store_result("siem_analysis", log_file, "analysis_completed")

    except Exception as e:
        OutputFormatter.print_message(f"[-] Error during SIEM log analysis: {e}", "error")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        OutputFormatter.print_message("Usage: python -m modules.siem_analysis <log_file>", "error")
        sys.exit(1)

    log_file = sys.argv[1]  # Get log file from CLI
    run(log_file)
