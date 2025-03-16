import subprocess
import os
import sys
import json
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from config.config import CONFIG
from .utils import log_event, init_db, store_result

# Initialize database
init_db()

# Paths from config
DISK_IMAGE = CONFIG.get("DISK_IMAGE_PATH", "samples/disk_image.dd")
MEMORY_DUMP = CONFIG.get("MEMORY_DUMP_PATH", "samples/memory.dmp")
ANALYSIS_OUTPUT = CONFIG.get("FORENSIC_REPORT", "output/forensic_results.json")


def analyze_disk(image_path):
    """Extract files and forensic artifacts from a disk image."""
    if not os.path.exists(image_path):
        log_event(f"Disk image {image_path} not found!", "error")
        return []
    
    try:
        result = subprocess.run(
            ["autopsy", "extract", "-i", image_path],
            capture_output=True, text=True
        )
        
        if result.returncode == 0 and result.stdout:
            extracted_data = result.stdout.strip().split("\n")
            artifacts = [{"file": item, "source": "disk", "timestamp": datetime.now().isoformat()} for item in extracted_data]
            
            for artifact in artifacts:
                store_result("forensic_disk", artifact["file"], "Extracted from disk image")
                log_event(f"[DISK] Extracted: {artifact['file']}")
            return artifacts
        
    except Exception as e:
        log_event(f"Disk analysis failed: {e}", "error")
        return []


def analyze_memory(memory_path):
    """Extract forensic artifacts from a memory dump."""
    if not os.path.exists(memory_path):
        log_event(f"Memory dump {memory_path} not found!", "error")
        return []
    
    try:
        result = subprocess.run(
            ["volatility", "-f", memory_path, "pslist"],
            capture_output=True, text=True
        )
        
        if result.returncode == 0 and result.stdout:
            processes = result.stdout.strip().split("\n")[1:]
            artifacts = [{"process": line, "source": "memory", "timestamp": datetime.now().isoformat()} for line in processes]
            
            for artifact in artifacts:
                store_result("forensic_memory", artifact["process"], "Detected in memory dump")
                log_event(f"[MEMORY] Found process: {artifact['process']}")
            return artifacts
        
    except Exception as e:
        log_event(f"Memory analysis failed: {e}", "error")
        return []


def save_results(results, output_file):
    """Save forensic analysis results to a JSON file."""
    try:
        with open(output_file, "w") as f:
            json.dump(results, f, indent=4)
        log_event(f"Results saved to {output_file}")
    except Exception as e:
        log_event(f"Failed to save results: {e}", "error")

def run():
    """Executes the forensic analysis on disk image and memory dump."""
    forensic_results = analyze_disk(DISK_IMAGE) + analyze_memory(MEMORY_DUMP)
    if forensic_results:
        save_results(forensic_results, ANALYSIS_OUTPUT)
    else:
        log_event("No forensic artifacts found.")

if __name__ == "__main__":
    run()
