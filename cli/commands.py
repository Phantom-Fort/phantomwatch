import json
import os
import sys
import readline
from dotenv import load_dotenv, dotenv_values, set_key
from config.config import CONFIG
from loguru import logger

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.output_formatter import OutputFormatter
from modules.utils import get_saved_results, get_api_key
from core.help import display_help
from modules import (
    incident_response, 
    siem_analysis, 
    threat_intel, 
    yara_scan, 
    malware_analysis, 
    osint_recon, 
    forensic_analysis, 
    websec_scanner, 
    network_scanner, 
    exploit_finder
)

logger.add("../logs/phantomwatch.log", rotation="10MB", level="INFO", format="{time} | {level} | {message}")

def log_message(message, msg_type="info"):
    """Logs messages using Loguru instead of print statements."""
    if msg_type == "success":
        logger.success(message)
    elif msg_type == "error":
        logger.error(message)
    elif msg_type == "warning":
        logger.warning(message)
    else:
        logger.info(message)

# Load environment variables from .env
load_dotenv()

# Load configuration from config.json
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "../config/config.json")
with open(CONFIG_PATH, "r") as config_file:
    CONFIG = json.load(config_file)

# Define module-specific flags
MODULE_FLAGS = {
    "incident-response": ["log file path"],
    "siem-analysis": ["siem-log file path"],
    "threat-intel": ["ip address", "domain", "hash"],
    "yara-scan": ["file"],
    "malware-analysis": ["sample file"],
    "osint-recon": ["domain", "email", "ip address"],
    "forensic-analysis": ["disk image", "memory dump"],
    "websec-scanner": ["url"],
    "network-scanner": ["network range"],
    "exploit-finder": ["cve-id", "software name"],
}

# Load available modules
MODULES = {
    "incident-response": incident_response.run,
    "siem-analysis": siem_analysis.run,
    "threat-intel": threat_intel.run,
    "yara-scan": yara_scan.run,
    "malware-analysis": malware_analysis.run,
    "osint-recon": osint_recon.run,
    "forensic-analysis": forensic_analysis.run,
    "websec-scanner": websec_scanner.run,
    "network-scanner": network_scanner.run,
    "exploit-finder": exploit_finder.run,
}

# Indicate modules with required API keys
MODULES["siem-analysis"].REQUIRED_API_KEY = "ELASTICSEARCH API"
MODULES["threat-intel"].REQUIRED_API_KEY = ["VIRUSTOTAL API", "MISP API", "MISP URL", "OTX API"]
MODULES["yara-scan"].REQUIRED_API_KEY = "HYBRIDANALYSIS API"
MODULES["malware-analysis"].REQUIRED_API_KEY = ["ANYRUN API", "HYBRIDANALYSIS API"]
MODULES["osint-recon"].REQUIRED_API_KEY = ["SHODAN API", "HUNTER API"]
MODULES["websec-scanner"].REQUIRED_API_KEY = "SECURITYTRAILS API"

def get_required_flag(module):
    """Retrieve the required flag for a module and prompt the user for input."""
    if module not in MODULE_FLAGS:
        OutputFormatter.print_message(f"[-] Error: Unknown module '{module}'.", "error")
        return None

    flags = MODULE_FLAGS[module]

    if len(flags) > 1:
        print(f"[INFO] The '{module}' module has multiple flag options:")
        for i, flag in enumerate(flags, start=1):
            print(f"  {i}. {flag}")

        try:
            flag_choice = int(input("Enter the number corresponding to the flag you want to use: ").strip())
            if 1 <= flag_choice <= len(flags):
                selected_flag = flags[flag_choice - 1]
            else:
                OutputFormatter.print_message(f"[-] Error: Invalid choice '{flag_choice}' for module '{module}'.", "error")
                return None
        except ValueError:
            OutputFormatter.print_message("[-] Error: Please enter a valid number.", "error")
            return None
    else:
        selected_flag = flags[0]

    user_input = input(f"Enter the {selected_flag}: ").strip()
    return {selected_flag: user_input}

def execute_module(module):
    """Executes the selected module after checking API key and collecting required flag input."""

    if module not in MODULES:
        OutputFormatter.print_message("[-] Invalid module specified. Use 'list-modules' to list available modules.", "error")
        log_message(f"Invalid module specified: {module}", "warning")
        return

    OutputFormatter.print_message(f"[+] Running module: {module}\n", "info")

    # Step 1: Check if the module requires an API key
    required_api_key = getattr(MODULES[module], "REQUIRED_API_KEY", None)

    if required_api_key:
        if isinstance(required_api_key, str):
            required_api_key = [required_api_key]  # Convert to list

        api_keys = get_api_key(required_api_key)

        for key in required_api_key:
            if key not in api_keys or not api_keys[key] or not api_keys[key].strip():
                return

        OutputFormatter.print_message(f"[INFO] API keys for '{module}' are set.\n", "info")
    else:
        OutputFormatter.print_message(f"[INFO] '{module}' is accessible offline.\n", "info")
    user_inputs = get_required_flag(module)
    if not user_inputs:
        return  # Abort execution if input is missing

    print(f"[DEBUG] Input: {user_inputs}")  # Debugging print

    # Step 3: Execute the module
    try:
        arg_value = user_inputs.popitem()[1]
        print(f"[DEBUG] Passing argument to {module}: {arg_value}")  # Debugging print
        MODULES[module](arg_value)
        OutputFormatter.print_message(f"[+] Module '{module}' executed successfully.", "success")
        log_message(f"Successfully executed module: {module}", "success")
    except TypeError as e:
        OutputFormatter.print_message(f"[-] Error: Unexpected arguments passed to module '{module}'.", "error")
        log_message(f"Module execution error: {str(e)}", "error")
    except Exception as e:
        OutputFormatter.print_message(f"[-] Error: Module '{module}' execution failed due to an exception.", "error")
        log_message(f"Execution failure: {str(e)}", "error")


def list_modules():
    """Lists available modules."""
    OutputFormatter.print_message("\nAvailable Modules:", "info")
    for mod in MODULES.keys():
        OutputFormatter.print_message(f"  - {mod}", "success")
    print("")

# List of commands for auto-completion

COMMANDS = ["help", "back", "list", "view-api", "use", "run", "set-api", "logs", "reports" "clear", "exit", "quit", "run {module}", "set-api {service} {api_key}", "use {module}"]


def completer(text, state):
    options = [cmd for cmd in COMMANDS if cmd.startswith(text)]
    return options[state] if state < len(options) else None

# Enable tab completion and command history
readline.parse_and_bind("tab: complete")
readline.set_completer(completer)

def interactive_shell():
    """Starts the enhanced interactive PhantomWatch shell."""
    OutputFormatter.print_message("\n[+] Welcome to PhantomWatch CLI. Type 'help' for a list of commands.\n", "info")
    
    selected_module = None  # Tracks the currently selected module

    while True:
        try:    
            prompt = f"phantomwatch{f'({selected_module})' if selected_module else ''}> "
            cmd = input(prompt).strip()
            
            if not cmd:
                continue  # Ignore empty commands

            log_message(f"Command entered: {cmd}", "info")

            if cmd.lower() in ["exit", "quit"]:
                OutputFormatter.print_message("[+] Exiting PhantomWatch CLI...", "info")
                break

            elif cmd.lower() == "help":
                display_help()

            elif cmd.lower() == "back":
                selected_module = None
                OutputFormatter.print_message("[+] Module deselected.", "info")

            elif cmd.lower() == "view-api":
                view_api_keys()

            elif cmd.lower() == "clear":
                os.system("clear")
            
            elif cmd.lower() == "logs":
                with open("logs/phantomwatch.log", "r") as log_file:
                    while True:
                        lines = log_file.readlines(50)
                        if not lines:
                            break
                        for line in lines:
                            print(line, end="")
                        user_input = input("\nPress Enter to continue or type 'q' to quit: ").strip().lower()
                        if user_input == 'q':
                            break

            elif cmd.lower() == "reports":
                if selected_module:
                    # Fetch and display the latest result for the selected module
                    results = get_saved_results(selected_module)
                    if results:
                        print(f"[+] Latest result for '{selected_module}': {results[-1]}")
                    else:
                        OutputFormatter.print_message(f"[-] No results found for '{selected_module}'.", "warning")
                else:
                    OutputFormatter.print_message("[-] No module selected. Use 'use <module>' first.", "error")

            elif cmd.lower().startswith("use "):
                if selected_module:
                    OutputFormatter.print_message("[-] A module is already selected. Use 'back' to deselect the current module first.", "error")
                else:
                    module = cmd.split(" ", 1)[1]
                    if module in MODULES:
                        selected_module = module
                        OutputFormatter.print_message(f"[+] Selected module: {module}", "success")
                    else:
                        OutputFormatter.print_message("[-] Error: Invalid module. Use 'list' to view available modules.", "error")

            elif cmd.lower() == "list":
                if selected_module:
                    OutputFormatter.print_message("[-] A module is already selected. Use 'back' to deselect the current module first.", "error")
                else:
                    list_modules()

            elif cmd.lower() == "run":
                if selected_module:
                    execute_module(selected_module)
                    os.system(f"phantomwatch -m {selected_module}")  # Execute via CLI, if applicable
                else:
                    OutputFormatter.print_message("[-] No module selected. Use 'use <module>' first.", "error")

            elif cmd.lower().startswith("run "):
                module = cmd.split(" ", 1)[1]
                execute_module(module)
                os.system(f"phantomwatch -m {module}")  # Execute via CLI, if applicable

            elif cmd.lower().startswith("set-api "):
                parts = cmd.split()
                if len(parts) == 3:
                    set_api_key(parts[1], parts[2])
                else:
                    OutputFormatter.print_message("[-] Usage: set-api <SERVICE> <API_KEY>", "error")

            else:
                OutputFormatter.print_message("[-] Invalid command. Type 'help' for a list of commands.", "error")
        except KeyboardInterrupt:
            OutputFormatter.print_message("\n[+] Exiting PhantomWatch CLI...", "info")
            break
        except Exception as e:
            log_message(f"Error: {e}", "error")
            OutputFormatter.print_message("[-] An error occurred. Check logs for details.", "error")

def set_api_key(service, api_key):
    """Sets an API key in the .env file."""
    env_path = CONFIG.get("env_path", os.path.join(os.path.dirname(__file__), "../config/secrets.env"))
    
    set_key(env_path, service.upper(), api_key)
    OutputFormatter.print_message(f"[+] API key for {service.upper()} set successfully.", "success")
    log_message(f"API key for {service.upper()} updated.")

def view_api_keys():
    """Lists the configured API keys without revealing sensitive values."""
    api_keys = dotenv_values(os.path.join(os.path.dirname(__file__), "../config/secrets.env"))

    if not api_keys:
        OutputFormatter.print_message("[-] No API keys configured.", "warning")
        return

    OutputFormatter.print_message("[+] Configured API Keys:", "info")
    for key, value in api_keys.items():
        hidden_value = value[:2] + "*" * (len(value) - 4) + value[-2:]  # Show first 2 and last 2 characters
        print(f"  - {key}: {hidden_value}")


def main():
    interactive_shell()


if __name__ == "__main__":
    main()
