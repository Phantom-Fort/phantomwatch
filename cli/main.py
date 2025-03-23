import time
import sys
import json
import os
from loguru import logger
from dotenv import load_dotenv

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from menu import menu
from core.banner import display_banner
from core.soc_tips import get_random_tips
from core.output_formatter import OutputFormatter

# Load environment variables
load_dotenv()

# Remove default handlers
logger.remove()

# Add a simpler handler for terminal output (no timestamps or log levels)
logger.add(sys.stdout, format="{message}", level="INFO")
logger.add("logs/phantomwatch.log", rotation="10MB", level="INFO", format="{time} | {level} | {message}")
logger.add("logs/error.log", rotation="10MB", level="ERROR", format="{time} | {level} | {message}")

# Load configuration file
INSTALL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONFIG_PATH = os.path.join(INSTALL_DIR, "config", "config.json")
CONFIG_PATH = os.path.normpath(CONFIG_PATH)

try:
    with open(CONFIG_PATH, "r") as config_file:
        CONFIG = json.load(config_file)
except (FileNotFoundError, json.JSONDecodeError) as e:
    OutputFormatter.log_message(f"Failed to load config from {CONFIG_PATH}: {e}", "error")
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
    initialize_phantomwatch()
    menu()

if __name__ == "__main__":
    main()
