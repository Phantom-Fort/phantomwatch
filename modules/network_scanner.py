import subprocess
import json
import re
import os
import sys
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from .utils import store_result, save_output
from core.output_formatter import OutputFormatter

def run_masscan(target, ports="1-65535", rate="10000"):
    """Runs Masscan for fast port scanning."""
    try:
        result = subprocess.run([
            "masscan", target, "-p", ports, "--rate", rate, "--output-format", "json"
        ], capture_output=True, text=True, check=True)
        return json.loads(result.stdout) if result.stdout else []
    except Exception as e:
        OutputFormatter.log_message(f"Masscan error: {str(e)}", "error")
        return {"error": str(e)}

def run_nmap(target, ports):
    """Runs Nmap for detailed service and vulnerability scanning."""
    try:
        result = subprocess.run([
            "nmap", "-sV", "-sC", "-p", ports, "--open", "-oX", "-", target
        ], capture_output=True, text=True, check=True)
        return parse_nmap_output(result.stdout)
    except Exception as e:
        OutputFormatter.log_message(f"Nmap error: {str(e)}", "error")
        return {"error": str(e)}

def parse_nmap_output(nmap_output):
    """Extracts relevant data from Nmap XML output."""
    parsed_data = []
    matches = re.findall(r'<port protocol="tcp" portid="(\d+)">.*?<state state="open"/>.*?<service name="(\w+)"', nmap_output, re.DOTALL)
    
    for port, service in matches:
        parsed_data.append({
            "port": port,
            "service": service,
            "timestamp": datetime.now().isoformat()
        })
    return parsed_data

def scan_network(target):
    """Performs a full network scan using Masscan & Nmap."""
    masscan_results = run_masscan(target)
    if "error" in masscan_results:
        return masscan_results
    
    open_ports = ",".join(str(item["port"] if "port" in item else "") for item in masscan_results)
    
    if open_ports:
        nmap_results = run_nmap(target, open_ports)
        return nmap_results
    else:
        return {"message": "No open ports found."}

def run(target_ip):
    """Scans a given network range."""
    
    if not target_ip:
        print("[-] Error: No network range provided.")
        return

    print(f"[+] Scanning network range: {target_ip}")

    try:
        results = scan_network(target_ip) or {}

        OutputFormatter.log_message(f"Scan results for {target_ip}: {json.dumps(results, indent=4)}", "info")
        store_result("network_scanner", target_ip, results)
        save_output("network_scan_results.json", results)

        print(json.dumps(results, indent=4))

    except Exception as e:
        print(f"[-] Error during network scan: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m modules.network_scanner <network_range>")
        sys.exit(1)

    target_ip = sys.argv[1]  # Get network range from CLI
    run(target_ip)

