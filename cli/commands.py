import argparse
import json
import os
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Load configuration from config.json
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "../config/config.json")
with open(CONFIG_PATH, "r") as config_file:
    CONFIG = json.load(config_file)

def set_api_key(service_name, api_key):
    """Saves the API key for a given service in the config file."""
    CONFIG["api_keys"][service_name.upper()] = api_key
    with open(CONFIG_PATH, "w") as config_file:
        json.dump(CONFIG, config_file, indent=4)
    print(f"[+] API key for {service_name} has been set successfully.")

def run_module(module_name):
    """Executes the specified module."""
    print(f"[+] Running module: {module_name}")
    # Placeholder for actual execution logic

def list_modules():
    """Lists available modules."""
    modules = CONFIG.get("modules", [
        "incident_response", "siem_correlation", "sigma_rules", 
        "threat_intel", "utils", "yara_scan"
    ])
    print("Available Modules:")
    for module in modules:
        print(f"  - {module}")

def main():
    parser = argparse.ArgumentParser(description="PhantomWatch Command Interface")
    parser.add_argument("-r", "--run", metavar="MODULE", help="Run a specific module")
    parser.add_argument("-l", "--list", action="store_true", help="List all available modules")
    parser.add_argument("--set-api", nargs=2, metavar=("SERVICE", "API_KEY"), help="Set API key for a service")

    args = parser.parse_args()
    
    if args.list:
        list_modules()
    elif args.run:
        run_module(args.run)
    elif args.set_api:
        service_name, api_key = args.set_api
        set_api_key(service_name, api_key)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
