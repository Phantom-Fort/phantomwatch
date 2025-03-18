import random
import pyfiglet
import socket

def is_connected():
    """Check if the system has an active internet connection."""
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=2)
        return True
    except OSError:
        return False
 
font_list = {"slant", "sub-zero", "lean", "shadow", "standard"}

def generate_ascii_art(text, width=100):
    """Generate ASCII art for the given text using pyfiglet."""
    font = random.choice(list(font_list))
    try:
        ascii_art = pyfiglet.figlet_format(text, font=font, width=width)
        return ascii_art
    except Exception:
        return None

def display_banner():
    # ANSI Escape Codes for Colors
    CYAN = "\033[96m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    if is_connected():
        # Generate ASCII Art Dynamically
        ascii_text = generate_ascii_art("PHANTOMWATCH")
        banner = f"{RED}{BOLD}\n{'-' * 100}\n{CYAN}{ascii_text}{CYAN}\n[ PHANTOMWATCH ] - Ultimate SOC Automation Tool\n{RESET}{'-' * 100}"
    else:
        # Default ASCII Banners (No Internet)
        default_banners = [
            rf"""
>>=================================================================================<<
|| ________  ___  ___  ________  ________   _________  ________  _____ ______      ||
|||\   __  \|\  \|\  \|\   __  \|\   ___  \|\___   ___\\   __  \|\   _ \  _   \    ||
||\ \  \|\  \ \  \\\  \ \  \|\  \ \  \\ \  \|___ \  \_\ \  \|\  \ \  \\\__\ \  \   ||
|| \ \   ____\ \   __  \ \   __  \ \  \\ \  \   \ \  \ \ \  \\\  \ \  \\|__| \  \  ||
||  \ \  \___|\ \  \ \  \ \  \ \  \ \  \\ \  \   \ \  \ \ \  \\\  \ \  \    \ \  \ ||
||   \ \__\    \ \__\ \__\ \__\ \__\ \__\\ \__\   \ \__\ \ \_______\ \__\    \ \__\||
|| ___\|__|  __ \|________\|_________|_________  ___|____ \|_______|\|__|     \|__|||
|||\  \     |\  \|\   __  \|\___   ___\\   ____\|\  \|\  \                         ||
||\ \  \    \ \  \ \  \|\  \|___ \  \_\ \  \___|\ \  \\\  \                        ||
|| \ \  \  __\ \  \ \   __  \   \ \  \ \ \  \    \ \   __  \                       ||
||  \ \  \|\__\_\  \ \  \ \  \   \ \  \ \ \  \____\ \  \ \  \                      ||
||   \ \____________\ \__\ \__\   \ \__\ \ \_______\ \__\ \__\                     ||
||    \|____________|\|__|\|__|    \|__|  \|_______|\|__|\|__|                     ||
||                                                                                 ||
||                                                                                 ||
||                 {RED}PHANTOMWATCH - Ultimate SOC Automation Tool{RESET}      ||
>>=================================================================================<<
            """
        ]
        banner = random.choice(default_banners)

    print(banner)

if __name__ == "__main__":
    display_banner()
