"""
CLI Package for PhantomWatch

This package contains the command-line interface (CLI) components of PhantomWatch, 
including command execution, menu navigation, and output formatting.
"""

import json
import os
from dotenv import load_dotenv
from loguru import logger

# Load environment variables
load_dotenv()

# Load configurations with error handling
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "../config/config.json")

CONFIG = {}

try:
    with open(CONFIG_PATH, "r") as config_file:
        CONFIG = json.load(config_file)
except (FileNotFoundError, json.JSONDecodeError) as e:
    logger.error(f"Failed to load configuration from {CONFIG_PATH}: {e}")
    CONFIG = {}  # Set default empty config to prevent crashes

# Import CLI components
from .commands import execute_command
from .menu import display_menu
from core.output_formatter import format_output

__all__ = ["execute_command", "display_menu", "format_output", "CONFIG"]
