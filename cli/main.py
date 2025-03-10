import argparse
import time
import sys
import json
import os
from dotenv import load_dotenv
from loguru import logger
from core.banner import display_banner
from core.soc_tips import get_random_tips
from core.output_formatter import OutputFormatter
from modules import incident_response, siem_correlation, sigma_rules, threat_intel, yara_scan

# Load environment variables
load_dotenv()

# Configure Loguru
logger.add("phantomwatch.log", rotation="10MB", level="INFO", format="{time} | {level} | {message}")

# Load configuration
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config/config.json")
try:
    with open(CONFIG_PATH, "r") as config_file:
        CONFIG = json.load(config_file)
except (FileNotFoundError, json.JSONDecodeError) as e:
    logger.error(f"Failed to load config: {e}")
    sys.exit(1)

# Dynamically load modules from config
MODULES = {
    module_name: globals().get(module_name.replace("-", "_"))
    for module_name in CONFIG.get("modules", [])
}

def initialize_phantomwatch():
    """Displays ASCII art, initializes PhantomWatch, and prints SOC tips."""
    display_banner()
    
    OutputFormatter.print_message("[+] Initializing PhantomWatch", "info")
    for _ in range(3):
        time.sleep(1)
        sys.stdout.write(".")
        sys.stdout.flush()
    print("\n")

    time.sleep(2)
    OutputFormatter.print_message("[+] Loading threat intelligence database...", "info")
    time.sleep(1)
    OutputFormatter.print_message("[+] Setting up automation scripts...\n", "info")
    time.sleep(1)

    soc_tips = get_random_tips(3)
    for tip in soc_tips:
        for char in tip:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(0.05)  # Typing effect
        print("\n")
        time.sleep(2)

    OutputFormatter.print_message("\n[+] Use --help to view available commands.", "success")
    OutputFormatter.print_message("[+] Note: 'utils' is not a module but contains universal parameters.", "warning")
    OutputFormatter.print_divider()

def execute_command(command, module):
    """Executes the specified command with an optional module."""
    if command == "list-modules":
        OutputFormatter.print_message("\nAvailable Modules:", "info")
        for mod in MODULES.keys():
            OutputFormatter.print_message(f"  - {mod}", "success")
        print("")
    elif command == "run" and module:
        if module in MODULES and MODULES[module]:
            OutputFormatter.print_message(f"Running module: {module}\n", "info")
            try:
                MODULES[module].run()
                logger.success(f"Successfully executed module: {module}")
            except AttributeError:
                OutputFormatter.print_message(f"Error: Selected module '{module}' does not have a 'run' function.", "error")
                logger.error(f"Module '{module}' is missing a 'run' function.")
        else:
            OutputFormatter.print_message(f"Invalid module '{module}'. Use 'list-modules' to view available modules.", "error")
            logger.warning(f"Invalid module specified: {module}")
    else:
        OutputFormatter.print_message("Invalid command. Use --help for available commands.", "error")
        logger.warning(f"Invalid command used: {command}")

def main():
    """Entry point for PhantomWatch CLI using argparse."""
    parser = argparse.ArgumentParser(description="PhantomWatch: Security Automation CLI")
    parser.add_argument("command", help="Command to execute")
    parser.add_argument("-m", "--module", help="Specify module to use")
    args = parser.parse_args()

    initialize_phantomwatch()
    execute_command(args.command, args.module)

if __name__ == "__main__":
    main()
