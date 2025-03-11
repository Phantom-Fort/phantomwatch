import argparse
import time
import sys
import json
import os
from loguru import logger

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.banner import display_banner
from core.soc_tips import get_random_tips
from core.output_formatter import OutputFormatter
from dotenv import load_dotenv
from commands import handle_command
from menu import interactive_shell

# Load environment variables
load_dotenv()

# Remove default handlers
logger.remove()

# Add a simpler handler for terminal output (no timestamps or log levels)
logger.add(sys.stdout, format="{message}", level="INFO")
logger.add("../logs/phantomwatch.log", rotation="10MB", level="INFO", format="{time} | {level} | {message}")

# Load configuration file
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config", "config.json")
CONFIG_PATH = os.path.normpath(CONFIG_PATH)

try:
    with open(CONFIG_PATH, "r") as config_file:
        CONFIG = json.load(config_file)
except (FileNotFoundError, json.JSONDecodeError) as e:
    logger.error(f"Failed to load config from {CONFIG_PATH}: {e}")
    sys.exit(1)

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
            time.sleep(0.05)
        print("\n")
        time.sleep(2)

    OutputFormatter.print_message("\n[+] Use 'help' to view the help page.", "success")
    OutputFormatter.print_divider()

def main():
    """Entry point for PhantomWatch CLI."""
    parser = argparse.ArgumentParser(description="PhantomWatch Interactive CLI")
    parser.add_argument("-l", "--list", action="store_true", help="List all available modules")
    parser.add_argument("-m", "--module", help="Run a specific module")
    parser.add_argument("--set-api", nargs=2, metavar=("SERVICE", "API_KEY"), help="Set API key for a service")
    args = parser.parse_args()

    initialize_phantomwatch()
    
    if args.command:
        handle_command(args.command)
    else:
        interactive_shell()

if __name__ == "__main__":
    main()
