#!/bin/bash

echo "[+] Installing PhantomWatch as a system package..."

# Install system dependencies
echo "[+] Installing required system dependencies..."
sudo apt install -y sqlite3 curl wget python3-venv make gcc

# Set up Python virtual environment
echo "[+] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo "[+] Installing Python dependencies..."
pip install -r requirements.txt

# Apply database schema
echo "[+] Setting up the database..."
sqlite3 database/phantomwatch.db < database/schema.sql

# Load environment variables from secrets.env
echo "[+] Loading environment variables..."
if [[ -f "config/secrets.env" ]]; then
    export $(grep -v '^#' config/secrets.env | xargs)
    echo "[+] Environment variables loaded!"
else
    echo "[-] Warning: secrets.env file not found. Skipping environment variable setup."
fi

# Ensure secrets.env is sourced in every new shell session
echo "[+] Persisting environment variables..."
if [[ "$SHELL" == */zsh ]]; then
    echo "source $(pwd)/config/secrets.env" >> ~/.zshrc
    source ~/.zshrc
elif [[ "$SHELL" == */bash ]]; then
    echo "source $(pwd)/config/secrets.env" >> ~/.bashrc
    source ~/.bashrc
else
    echo "[-] Warning: Unable to determine shell. Add 'source $(pwd)/config/secrets.env' manually to your shell profile."
fi

# Make PhantomWatch executable system-wide
echo "[+] Setting up PhantomWatch as a CLI tool..."
chmod +x cli/main.py
sudo cp cli/main.py /usr/local/bin/phantomwatch

# Add execution permissions
sudo chmod +x /usr/local/bin/phantomwatch

echo "[+] Installation complete! You can now run PhantomWatch using the command: phantomwatch"
echo "[+] Please restart your shell to apply the changes."
