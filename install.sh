#!/bin/bash

echo "[+] Installing PhantomWatch as a system package..."

# Update package lists
echo "[+] Updating package lists..."
sudo apt update -y

# Install system dependencies
echo "[+] Installing required system dependencies..."
sudo apt install -y python3 python3-pip sqlite3

# Create a virtual environment
echo "[+] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo "[+] Installing Python dependencies..."
pip install -r requirements.txt

# Apply database schema
echo "[+] Setting up the database..."
sqlite3 database/phantomwatch.db < database/schema.sql

# Load environment variables
echo "[+] Loading environment variables..."
export $(grep -v '^#' config/secrets.env | xargs)

# Make PhantomWatch executable system-wide
echo "[+] Setting up PhantomWatch as a CLI tool..."
chmod +x cli/main.py
sudo cp cli/main.py /usr/local/bin/phantomwatch

# Add execution permissions
sudo chmod +x /usr/local/bin/phantomwatch

echo "[+] Installation complete! You can now run PhantomWatch using the command: phantomwatch"
