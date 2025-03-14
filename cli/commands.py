import json
import os
import sys
import readline
from loguru import logger
from dotenv import load_dotenv, set_key, dotenv_values

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.output_formatter import OutputFormatter
from modules.utils import log_event
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
    "incident-response": incident_response,
    "siem-analysis": siem_analysis,
    "threat-intel": threat_intel,
    "yara-scan": yara_scan,
    "malware-analysis": malware_analysis,
    "osint-recon": osint_recon,
    "forensic-analysis": forensic_analysis,
    "websec-scanner": websec_scanner,
    "network-scanner": network_scanner,
    "exploit-finder": exploit_finder,
}


def get_required_flags(module):
    """Prompts user for required flags before executing a module."""
    required_flags = MODULE_FLAGS.get(module, [])
    user_inputs = {}

    for flag in required_flags:
        value = input(f"Enter value for {flag}: ").strip()
        if value:
            user_inputs[flag] = value
        else:
            OutputFormatter.print_message(f"[-] Error: {flag} is required.", "error")
            return None  # Exit if a required input is missing

    return user_inputs

def execute_module(module):
    """Executes the specified module after collecting necessary inputs."""
    if module in MODULES:
        OutputFormatter.print_message(f"[+] Running module: {module}\n", "info")

        # Check if the module requires an API key
        required_api_key = MODULES[module].REQUIRED_API_KEY if hasattr(MODULES[module], "REQUIRED_API_KEY") else None
        
        if required_api_key:
            api_keys = dotenv_values(os.path.join(os.path.dirname(__file__), "../.env"))

            if required_api_key not in api_keys or not api_keys[required_api_key].strip():
                OutputFormatter.print_message(f"[-] Error: The module '{module}' requires the API key '{required_api_key}' to be set.", "error")
                
                set_key = input(f"Do you want to set the API key for '{required_api_key}' now? (y/n): ").strip().lower()
                if set_key == "y":
                    new_api_key = input(f"Enter the API key for '{required_api_key}': ").strip()
                    if new_api_key:
                        with open(os.path.join(os.path.dirname(__file__), "../.env"), "a") as env_file:
                            env_file.write(f"\n{required_api_key}={new_api_key}")
                        OutputFormatter.print_message(f"[+] API key for '{required_api_key}' has been set.", "success")
                    else:
                        OutputFormatter.print_message("[-] No API key provided. Module execution aborted.", "error")
                        return
                else:
                    OutputFormatter.print_message("[-] API key not set. Module execution aborted.", "error")
                    return

        # Handle multiple flags for modules like threat-intel
        if module == "threat-intel":
            flag_choice = input("Enter the flag to use (`1` for IP address / `2` for domain): ").strip()
            if flag_choice == "1":
                flag = "ip address"
            elif flag_choice == "2":
                flag = "domain"
            else:
                OutputFormatter.print_message(f"[-] Error: Invalid choice '{flag_choice}' for module '{module}'.", "error")
                return  # Exit function if invalid choice
            
            user_inputs = {flag: input(f"Enter the {flag}: ").strip()}  # Prompt user for input
        
        else:
            # Get required flags from user
            user_inputs = get_required_flags(module)

        if not user_inputs:
            return  # Abort execution if missing input

        try:
            # Pass user inputs as arguments to the module's run() function
            MODULES[module].run(**user_inputs)
            logger.success(f"Successfully executed module: {module}")
        except AttributeError:
            log_event("[-] Error: Selected module does not have a 'run' function.", "error")
            logger.error(f"Module '{module}' is missing a 'run' function.")
    else:
        OutputFormatter.print_message("[-] Invalid module specified. Use 'list-modules' to list available modules.", "error")
        logger.warning(f"Invalid module specified: {module}")

def list_modules():
    """Lists available modules."""
    OutputFormatter.print_message("\nAvailable Modules:", "info")
    for mod in MODULES.keys():
        OutputFormatter.print_message(f"  - {mod}", "success")
    print("")


# List of commands for auto-completion

COMMANDS = ["help", "list-modules", "view-api", "use", "run", "set-api", "clear", "exit", "quit", "run {module}", "set-api {service} {api_key}", "use {module}"]


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
            prompt = f"phantomwatch{f'/{selected_module}' if selected_module else ''}> "
            cmd = input(prompt).strip()
            
            if not cmd:
                continue  # Ignore empty commands

            logger.info(f"Command entered: {cmd}")

            if cmd.lower() in ["exit", "quit"]:
                OutputFormatter.print_message("[+] Exiting PhantomWatch CLI...", "info")
                break

            elif cmd.lower() == "help":
                display_help()

            elif cmd.lower() == "list-modules":
                list_modules()

            elif cmd.lower() == "view-api":
                view_api_keys()

            elif cmd.lower() == "clear":
                os.system("clear")

            elif cmd.lower().startswith("use "):
                module = cmd.split(" ", 1)[1]
                if module in MODULES:
                    selected_module = module
                    OutputFormatter.print_message(f"[+] Selected module: {module}", "success")
                else:
                    OutputFormatter.print_message("[-] Error: Invalid module. Use 'list-modules' to view available modules.", "error")

            elif cmd.lower() == "run":
                if selected_module:
                    OutputFormatter.print_message(f"[+] Running selected module: {selected_module}", "info")
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
            logger.error(f"Error: {e}")
            OutputFormatter.print_message("[-] An error occurred. Check logs for details.", "error")


def set_api_key(service, api_key):
    """Sets an API key in the .env file."""
    env_path = os.path.join(os.path.dirname(__file__), "../.env")
    
    set_key(env_path, service.upper(), api_key)
    OutputFormatter.print_message(f"[+] API key for {service.upper()} set successfully.", "success")
    logger.info(f"API key for {service.upper()} updated.")


def view_api_keys():
    """Lists the configured API keys without revealing sensitive values."""
    api_keys = dotenv_values(os.path.join(os.path.dirname(__file__), "../.env"))

    if not api_keys:
        OutputFormatter.print_message("[-] No API keys configured.", "warning")
        return

    OutputFormatter.print_message("[+] Configured API Keys:", "info")
    for key in api_keys:
        print(f"  - {key}: [HIDDEN]")  # Hide actual values


def main():
    interactive_shell()


if __name__ == "__main__":
    main()
