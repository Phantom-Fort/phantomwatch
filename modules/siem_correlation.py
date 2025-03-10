import sqlite3
import json
from datetime import datetime
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from .utils import log_event, init_db, store_result
from config.config import CONFIG  # Import config

# Initialize Database
init_db()

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
    
    conn.close()
    
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
    
    output_file = "correlation_results.json"
    with open(output_file, "w") as f:
        json.dump(correlation_results, f, indent=4)
    
    log_event(f"[INFO] Correlated {len(correlation_results)} events. Output saved to {output_file}")
    return correlation_results

if __name__ == "__main__":
    results = correlate_events()
    print(json.dumps(results, indent=4))
