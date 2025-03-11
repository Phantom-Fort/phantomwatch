#!/bin/bash

echo "[+] Installing PhantomWatch as a system package..."

# Install system dependencies
echo "[+] Installing required system dependencies..."
sudo apt update
sudo apt install -y sqlite3 curl

# Download and install YARA binary
echo "[+] Downloading YARA binary..."
YARA_VERSION="4.3.2"  # Change version if needed
ARCH=$(uname -m)
YARA_URL="https://github.com/VirusTotal/yara/releases/download/v$YARA_VERSION/yara-${YARA_VERSION}-${ARCH}.tar.gz"

curl -L $YARA_URL -o yara.tar.gz
mkdir -p yara_bin
tar -xzf yara.tar.gz -C yara_bin --strip-components=1
sudo mv yara_bin/yara /usr/local/bin/
rm -rf yara_bin yara.tar.gz

# Verify YARA installation
if ! command -v yara &> /dev/null; then
    echo "[ERROR] YARA installation failed!"
    exit 1
else
    echo "[+] YARA installed successfully!"
fi

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
