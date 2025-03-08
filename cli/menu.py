import argparse
import json
import os
from dotenv import load_dotenv
from loguru import logger
from core.output_formatter import OutputFormatter
from modules import incident_response, siem_correlation, sigma_rules, threat_intel, yara_scan

# Load environment variables
load_dotenv()

# Configure Loguru
logger.add("phantomwatch.log", rotation="10MB", level="INFO", format="{time} | {level} | {message}")

# Load configuration file
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config/config.json")

try:
    with open(CONFIG_PATH, "r") as config_file:
        CONFIG = json.load(config_file)
except (FileNotFoundError, json.JSONDecodeError) as e:
    logger.error(f"Failed to load config: {e}")
    OutputFormatter.print_message("[-] Error: Failed to load configuration file.", "error")
    exit(1)

# Dynamically load modules from config
MODULES = {
    module_name: globals().get(module_name.replace("-", "_"))
    for module_name in CONFIG.get("modules", [])
}

def list_modules():
    """Lists available modules."""
    OutputFormatter.print_message("\nAvailable Modules:", "info")
    for mod in MODULES.keys():
        OutputFormatter.print_message(f"  - {mod}", "success")
    print("")

def execute_module(module):
    """Executes the specified module."""
    if module in MODULES and MODULES[module]:
        OutputFormatter.print_message(f"[+] Running module: {module}\n", "info")
        try:
            MODULES[module].run()
            logger.success(f"Successfully executed module: {module}")
        except AttributeError:
            OutputFormatter.print_message("[-] Error: Selected module does not have a 'run' function.", "error")
            logger.error(f"Module '{module}' is missing a 'run' function.")
    else:
        OutputFormatter.print_message("[-] Invalid module specified. Use 'list-modules' to view available modules.", "error")
        logger.warning(f"Invalid module specified: {module}")

def main():
    """Main entry point for the PhantomWatch menu system."""
    parser = argparse.ArgumentParser(description="PhantomWatch Interactive Menu")
    parser.add_argument("command", choices=["list-modules", "run"], help="Command to execute")
    parser.add_argument("-m", "--module", help="Specify module to run (if applicable)")
    args = parser.parse_args()
    
    if args.command == "list-modules":
        list_modules()
    elif args.command == "run":
        if args.module:
            execute_module(args.module)
        else:
            OutputFormatter.print_message("[-] Error: Please specify a module with -m <module_name>.", "error")

if __name__ == "__main__":
    main()
