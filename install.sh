#!/bin/bash

echo "[+] Installing PhantomWatch as a system package..."

# Install system dependencies
sudo apt update -qq && sudo apt install -y -qq sqlite3 curl wget python3-venv make gcc python3-pip

# Set up Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install PhantomWatch as a package
pip install .

echo "[+] Installation complete! You can now run PhantomWatch using: phantomwatch"
