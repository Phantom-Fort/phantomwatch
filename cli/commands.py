import json
import os
import sys
import readline
from dotenv import load_dotenv, dotenv_values, set_key
from config.config import CONFIG

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.output_formatter import OutputFormatter
from modules.utils import log_event, get_saved_results, get_api_key
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

def get_user_inputs(module):
    """Prompt the user for required inputs based on the module's flags."""
    if module not in MODULE_FLAGS:
        OutputFormatter.print_message(f"[-] Error: Unknown module '{module}'.", "error")
        return None  # Exit if module is invalid

    flags = MODULE_FLAGS[module]
    user_inputs = {}

    # If multiple flags exist, prompt the user to select one
    if len(flags) > 1:
        print(f"[INFO] The '{module}' module has multiple flag options:")
        for i, flag in enumerate(flags, start=1):
            print(f"  {i}. {flag}")

        flag_choice = input("Enter the number corresponding to the flag you want to use: ").strip()
        try:
            flag_choice = int(flag_choice)
            if 1 <= flag_choice <= len(flags):
                selected_flag = flags[flag_choice - 1]
            else:
                OutputFormatter.print_message(f"[-] Error: Invalid choice '{flag_choice}' for module '{module}'.", "error")
                return None
        except ValueError:
            OutputFormatter.print_message(f"[-] Error: Please enter a valid number for module '{module}'.", "error")
            return None
    else:
        selected_flag = flags[0]  # Use the only available flag

    user_inputs[selected_flag] = input(f"Enter the {selected_flag}: ").strip()
    return user_inputs  # Return user input as a dictionary

def execute_module(module):
    """Executes the specified module after collecting necessary inputs."""

    if module not in MODULES:
        OutputFormatter.print_message("[-] Invalid module specified. Use 'list-modules' to list available modules.", "error")
        log_event(f"Invalid module specified: {module}", "warning")
        return

    OutputFormatter.print_message(f"[+] Running module: {module}\n", "info")

    # Check if the module requires an API key
    required_api_key = getattr(MODULES[module], "REQUIRED_API_KEY", None)

    if required_api_key:
        api_keys = get_api_key(required_api_key)

        if required_api_key not in api_keys or not api_keys[required_api_key].strip():
            OutputFormatter.print_message(f"[-] Error: The module '{module}' requires the API key '{required_api_key}' to be set.", "error")
            
            set_key = input(f"Do you want to set the API key for '{required_api_key}' now? (y/n): ").strip().lower()
            if set_key == "y":
                OutputFormatter.print_message(f"Use the command 'set-api {required_api_key} <your_api_key>' to set the API key.", "info")
            else:
                OutputFormatter.print_message("[-] API key not set. Module execution aborted.", "error")
            return

    # Collect user inputs based on the module's required flags
    user_inputs = get_user_inputs(module)
    if not user_inputs:
        return  # Abort execution if missing inputt

    # Execute the module safely
    try:
        MODULES[module](**user_inputs)
        OutputFormatter.print_message(f"[+] Module '{module}' executed successfully.", "success")
        log_event(f"Successfully executed module: {module}", "success")
    except AttributeError:
        OutputFormatter.print_message(f"[-] Error: Module '{module}' execution failed.", "error")
        log_event(f"Module '{module}' is missing a 'run' function.", "error")
    except Exception as e:
        log_event(f"Error executing module '{module}': {str(e)}", "error")

def list_modules():
    """Lists available modules."""
    OutputFormatter.print_message("\nAvailable Modules:", "info")
    for mod in MODULES.keys():
        OutputFormatter.print_message(f"  - {mod}", "success")
    print("")

# List of commands for auto-completion

COMMANDS = ["help", "back", "list-modules", "view-api", "use", "run", "set-api", "logs", "reports" "clear", "exit", "quit", "run {module}", "set-api {service} {api_key}", "use {module}"]


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

            log_event(f"Command entered: {cmd}", "info")

            if cmd.lower() in ["exit", "quit"]:
                OutputFormatter.print_message("[+] Exiting PhantomWatch CLI...", "info")
                break

            elif cmd.lower() == "help":
                display_help()

            elif cmd.lower() == "back":
                selected_module = None
                OutputFormatter.print_message("[+] Module deselected.", "info")

            elif cmd.lower() == "list-modules":
                list_modules()

            elif cmd.lower() == "view-api":
                view_api_keys()

            elif cmd.lower() == "clear":
                os.system("clear")
            
            elif cmd.lower() == "logs":
                os.system("less logs/phantomwatch.log")

            elif cmd.lower() == "reports":
                # List available tables
                tables = get_saved_results("tables")
                if not tables:
                    OutputFormatter.print_message("[-] No tables found.", "warning")
                    continue

                print("[INFO] Available tables:")
                for i, table in enumerate(tables, start=1):
                    print(f"  {i}. {table}")

                table_choice = input("Enter the number corresponding to the table you want to view: ").strip()
                try:
                    table_choice = int(table_choice)
                    if 1 <= table_choice <= len(tables):
                        selected_table = tables[table_choice - 1]
                    else:
                        OutputFormatter.print_message(f"[-] Error: Invalid choice '{table_choice}'.", "error")
                        continue
                except ValueError:
                    OutputFormatter.print_message(f"[-] Error: Please enter a valid number.", "error")
                    continue

                # Fetch and display results from the selected table
                results = get_saved_results(selected_table)
                if results:
                    print(f"[+] Latest result from '{selected_table}': {results[0]}")
                else:
                    OutputFormatter.print_message(f"[-] No results found in '{selected_table}'.", "warning")

            elif cmd.lower().startswith("use "):
                module = cmd.split(" ", 1)[1]
                if module in MODULES:
                    selected_module = module
                    OutputFormatter.print_message(f"[+] Selected module: {module}", "success")
                else:
                    OutputFormatter.print_message("[-] Error: Invalid module. Use 'list-modules' to view available modules.", "error")

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
            log_event(f"Error: {e}", "error")
            OutputFormatter.print_message("[-] An error occurred. Check logs for details.", "error")

def set_api_key(service, api_key):
    """Sets an API key in the .env file."""
    env_path = CONFIG.get("env_path", os.path.join(os.path.dirname(__file__), "../config/secrets.env"))
    
    set_key(env_path, service.upper(), api_key)
    OutputFormatter.print_message(f"[+] API key for {service.upper()} set successfully.", "success")
    log_event(f"API key for {service.upper()} updated.")

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
