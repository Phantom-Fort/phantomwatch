import subprocess
import os
import sys
import json
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from config.config import CONFIG
from .utils import log_event, init_db, store_result, save_output

# Initialize database
init_db()

# Paths from config
DISK_IMAGE = CONFIG.get("DISK_IMAGE_PATH", "../samples/disk_image.dd")
MEMORY_DUMP = CONFIG.get("MEMORY_DUMP_PATH", "../samples/memory.dmp")
ANALYSIS_OUTPUT = CONFIG.get("FORENSIC_REPORT", "../output/forensic_reports.json")


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
                log_event(f"[DISK] Extracted: {artifact['file']}", "info")
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
                log_event(f"[MEMORY] Found process: {artifact['process']}", "info")
            return artifacts
        
    except Exception as e:
        log_event(f"Memory analysis failed: {e}", "error")
        return []


def run(file_path):
    """Executes forensic analysis on either a disk image or a memory dump."""
    
    if not file_path:
        log_event("Missing required forensic analysis input.", "error")
        return
    
    forensic_results = []
    
    if file_path.endswith(".img"):  # Disk Image Analysis
        forensic_results = analyze_disk(file_path)
    elif file_path.endswith(".dmp"):  # Memory Dump Analysis
        forensic_results = analyze_memory(file_path)
    else:
        log_event("Invalid file format. Provide a valid disk image (.img) or memory dump (.dmp).", "error")
        return

    if forensic_results:
        save_output(forensic_results, ANALYSIS_OUTPUT)
        store_result("forensic_analysis", ANALYSIS_OUTPUT, "Forensic artifacts extracted")
    else:
        log_event("No forensic artifacts found.", "warning")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m modules.forensic_analysis <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]  # Accepts either a disk image or a memory dump
    run(file_path)

