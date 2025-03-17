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

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from .utils import log_event, init_db, store_siem_results, store_sigma_match, save_output
from config.config import CONFIG

# Initialize Database
init_db()

# Elasticsearch Configuration
ELASTICSEARCH_HOST = "http://localhost:9200"
INDEX_NAME = "logs-*"
SIGMA_RULES_FILE = CONFIG["SIGMA_RULES_PATH"]

# Initialize Elasticsearch client
es = Elasticsearch([ELASTICSEARCH_HOST])

# Load Sigma rules
def load_sigma_rules(rule_file):
    if not os.path.exists(rule_file):
        log_event(f"[ERROR] Sigma rule file not found: {rule_file}", "error")
        return []
    try:
        with open(rule_file, "r") as f:
            parser = SigmaCollectionParser(f.read(), SigmaRule())
            backend = LuceneBackend(SigmaRule())
            return [backend.convert(rule) for rule in parser.rules]
    except yaml.YAMLError as e:
        log_event(f"[ERROR] Error parsing Sigma rules YAML: {e}", "error")
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
    
    log_event(f"[INFO] Correlated {len(correlation_results)} events.", "info")
    return correlation_results

# Main execution function
def analyze_siem_logs():
    try:
        alerts = search_logs_with_sigma()
        correlation_results = correlate_events()
        
        if alerts or correlation_results:
            print("[ALERT] Potential Threats Detected!")
            print(json.dumps({"alerts": alerts, "correlations": correlation_results}, indent=2))
        else:
            print("[INFO] No threats detected in logs.")
    except Exception as e:
        log_event(f"[ERROR] Log analysis failed {str(e)}", "error")

def run():
    analyze_siem_logs()

if __name__ == "__main__":
    run()
