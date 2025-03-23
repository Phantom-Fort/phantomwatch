import os
import sys
import json
from loguru import logger

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.output_formatter import OutputFormatter
from dotenv import load_dotenv
from commands import interactive_shell

# Load environment variables
load_dotenv()

# Configure Loguru logger
logger.add("logs/phantomwatch.log", rotation="10MB", level="INFO", format="{time} | {level} | {message}")

# Load configuration file
INSTALL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONFIG_PATH = os.path.join(INSTALL_DIR, "config", "config.json")

try:
    with open(CONFIG_PATH, "r") as config_file:
        CONFIG = json.load(config_file)
except (FileNotFoundError, json.JSONDecodeError) as e:
    logger.error(f"Failed to load config: {e}")
    OutputFormatter.print_message("[-] Error: Failed to load configuration file.", "error")
    exit(1)


def menu():
    """Main entry point for PhantomWatch CLI."""
    interactive_shell()

if __name__ == "__main__":
    menu()
