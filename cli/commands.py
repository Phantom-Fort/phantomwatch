import argparse
import json
import os
import sys
from loguru import logger
from dotenv import load_dotenv, set_key, dotenv_values

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.output_formatter import OutputFormatter
from modules.utils import log_event
from core.help import display_help
from modules import incident_response, siem_correlation, sigma_rules, threat_intel, yara_scan

# Load environment variables from .env
load_dotenv()

# Load configuration from config.json
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "../config/config.json")
with open(CONFIG_PATH, "r") as config_file:
    CONFIG = json.load(config_file)

def handle_command(command):
    """Processes user commands interactively."""
    parts = command.strip().split()
    
    if not parts:
        return  # Ignore empty input
    
    cmd = parts[0].lower()
    args = parts[1:] if len(parts) > 1 else []

    if cmd == "-l":
        list_modules()
    
    elif cmd == "run":
        if args:
            module = args[0]
            execute_module(module)
        else:
            OutputFormatter.print_message("[-] Error: Specify a module with 'run <module>'", "error")

    elif cmd == "set-api":
        if len(args) < 2:
            OutputFormatter.print_message("[-] Error: Usage - set-api <SERVICE> <API_KEY>", "error")
        else:
            set_api_key(args[0], args[1])

    elif cmd == "view-api":
        view_api_keys()

    elif cmd in ["exit", "quit"]:
        OutputFormatter.print_message("[+] Exiting PhantomWatch...", "info")
        sys.exit(0)

    else:
        OutputFormatter.print_message(f"[-] Unknown command: {cmd}. ", "error")
        logger.warning(f"Invalid command received: {cmd}")

# Define module-specific flags
MODULE_FLAGS = {
    "incident-response": ["log file path"],
    "siem-correlation": ["siem-log file path"],
    "sigma-rules": ["log file path"],
    "threat-intel": ["ip address", "domain"],
    "yara-scan": ["file"],
}

# Load available modules
MODULES = {
    "incident-response": incident_response,
    "siem-correlation": siem_correlation,
    "sigma-rules": sigma_rules,
    "threat-intel": threat_intel,
    "yara-scan": yara_scan,
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

        # Handle multiple flags for modules like threat-intel
        if module == "threat-intel":
            flag_choice = input("Enter the flag to use (`1` for ip address / `2` for domain): ").strip()
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

def interactive_shell():
    """Starts the interactive PhantomWatch shell."""
    OutputFormatter.print_message("\n[+] Welcome to PhantomWatch CLI. Type 'help' for a list of commands.\n", "info")

    selected_module = None  # Tracks the currently selected module

    while True:
        try:
            prompt = f"phantomwatch{f'/{selected_module}' if selected_module else ''}> "
            cmd = input(prompt).strip()

            if cmd in ["exit", "quit"]:
                OutputFormatter.print_message("[+] Exiting PhantomWatch CLI...", "info")
                break
            elif cmd == "help":
                display_help()
            elif cmd == "list-modules":
                list_modules()
            elif cmd == "view-api":
                view_api_keys()
            elif cmd.startswith("use "):
                module = cmd.split(" ", 1)[1]
                if module in MODULES:
                    selected_module = module
                    OutputFormatter.print_message(f"[+] Selected module: {module}", "success")
                else:
                    OutputFormatter.print_message("[-] Error: Invalid module. Use 'list-modules' to view available modules.", "error")
            elif cmd == "run":
                if selected_module:
                    OutputFormatter.print_message(f"[+] Running selected module: {selected_module}", "info")
                    execute_module(selected_module)
                    os.system(f"phantomwatch -m {selected_module}")  # Execute via CLI
                else:
                    OutputFormatter.print_message("[-] No module selected. Use 'select <module>' first.", "error")
            elif cmd.startswith("run "):
                module = cmd.split(" ", 1)[1]
                execute_module(module)
                os.system(f"phantomwatch -m {module}")  # Execute via CLI
            elif cmd.startswith("set-api "):
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
    """Entry point for the PhantomWatch CLI."""
    parser = argparse.ArgumentParser(description="PhantomWatch Command Interface")
    parser.add_argument("cli", nargs="?", help="Start the interactive shell")
    args = parser.parse_args()
    
    if args.cli:
        interactive_shell()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
