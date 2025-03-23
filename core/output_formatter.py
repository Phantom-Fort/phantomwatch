import json
import os
from tabulate import tabulate
from loguru import logger

class OutputFormatter:
    # ANSI color codes for terminal formatting
    COLORS = {
        "success": "\033[92m",  # Green
        "error": "\033[91m",    # Red
        "warning": "\033[93m",  # Yellow
        "info": "\033[94m",     # Blue
        "reset": "\033[0m"      # Reset
    }

    # Check if ANSI colors should be disabled (e.g., Windows CMD)
    DISABLE_COLORS = os.getenv("DISABLE_COLORS", "false").lower() == "true"

    # Configure Loguru
    logger.add("logs/phantomwatch.log", rotation="10MB", level="INFO", format="{time} | {level} | {message}")

    @staticmethod
    def format_message(message, msg_type="info"):
        """Formats a message with optional color coding."""
        if OutputFormatter.DISABLE_COLORS:
            return message  # Return plain text if colors are disabled
        color = OutputFormatter.COLORS.get(msg_type, OutputFormatter.COLORS["info"])
        return f"{color}{message}{OutputFormatter.COLORS['reset']}"
    
    @staticmethod
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

    @staticmethod
    def print_message(message, msg_type="info"):
        colors = {
            "info": "\033[94m",     # Blue
            "success": "\033[92m",  # Green
            "warning": "\033[93m",  # Yellow
            "error": "\033[91m",    # Red
            "reset": "\033[0m"
        }

        color = colors.get(msg_type, colors["info"])
        print(f"{color}{message}{colors['reset']}")  # Print without logging

    @staticmethod
    def format_table(data, headers=None):
        """Formats data as a structured table using tabulate."""
        if not data:
            return "No data available."
        return tabulate(data, headers=headers or [], tablefmt="grid")

    @staticmethod
    def print_table(data, headers=None):
        """Prints data in a well-formatted table and logs it."""
        table = OutputFormatter.format_table(data, headers)
        print(table)
        OutputFormatter.log_message(f"\n{table}", "info")

    @staticmethod
    def format_json(data):
        """Formats dictionary data as a pretty JSON string."""
        return json.dumps(data, indent=4, sort_keys=True)

    @staticmethod
    def print_json(data):
        """Prints formatted JSON output and logs it."""
        json_output = OutputFormatter.format_json(data)
        print(json_output)
        OutputFormatter.log_message(json_output, "info")

    @staticmethod
    def print_divider(char="-", length=50):
        """Prints a visual divider line."""
        divider = char * length
        print(divider)
        OutputFormatter.print_message(divider, "info")

    @staticmethod
    def print_header(title):
        """Prints a stylized header with dividers."""
        OutputFormatter.print_divider("=")
        OutputFormatter.print_message(f"[ {title.upper()} ]", "info")
        OutputFormatter.print_divider("=")
