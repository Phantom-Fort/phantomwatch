import os
import sys
import argparse
import json
from loguru import logger

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.output_formatter import OutputFormatter
from dotenv import load_dotenv
from commands import list_modules, execute_module, interactive_shell, set_api_key

# Load environment variables
load_dotenv()

# Configure Loguru logger
logger.add("../logs/phantomwatch.log", rotation="10MB", level="INFO", format="{time} | {level} | {message}")

# Load configuration file
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "../config/config.json")
try:
    with open(CONFIG_PATH, "r") as config_file:
        CONFIG = json.load(config_file)
except (FileNotFoundError, json.JSONDecodeError) as e:
    logger.error(f"Failed to load config: {e}")
    OutputFormatter.print_message("[-] Error: Failed to load configuration file.", "error")
    exit(1)


def main():
    """Main entry point for PhantomWatch CLI."""
    parser = argparse.ArgumentParser(description="PhantomWatch Interactive CLI")
    parser.add_argument("-l", "--list", action="store_true", help="List all available modules")
    parser.add_argument("-m", "--module", help="Run a specific module")
    parser.add_argument("--set-api", nargs=2, metavar=("SERVICE", "API_KEY"), help="Set API key for a service")
    args = parser.parse_args()
    
    if args.list:
        list_modules()
    elif args.module:
        execute_module(args.module)
    elif args.set_api:
        set_api_key(args.set_api[0], args.set_api[1])
    else:
        interactive_shell()

if __name__ == "__main__":
    main()
