#!/bin/bash

echo "[+] Installing PhantomWatch as a system package..."

# Install system dependencies
echo "[+] Installing required system dependencies..."
sudo apt update
sudo apt install -y sqlite3 curl

echo "[+] Checking for the latest YARA version..."
YARA_LATEST=$(curl -s https://api.github.com/repos/VirusTotal/yara/releases/latest | grep -oP '"tag_name": "\K(.*?)(?=")')

if [[ -z "$YARA_LATEST" ]]; then
    echo "[-] Error: Unable to fetch the latest YARA version."
    exit 1
fi

echo "[+] Latest YARA version found: $YARA_LATEST"

ARCH=$(uname -m)
if [[ "$ARCH" == "x86_64" ]]; then
    ARCH="amd64"
elif [[ "$ARCH" == "aarch64" ]]; then
    ARCH="arm64"
fi

YARA_URL="https://github.com/VirusTotal/yara/releases/download/${YARA_LATEST}/yara-${YARA_LATEST}-${ARCH}.tar.gz"

echo "[+] Downloading YARA binary from $YARA_URL..."
wget -q --show-progress "$YARA_URL" -O yara.tar.gz

if [[ $? -ne 0 ]]; then
    echo "[-] Error: Failed to download YARA binary."
    exit 1
fi

echo "[+] Extracting YARA..."
tar -xzf yara.tar.gz
cd yara-* || exit 1

echo "[+] Installing YARA..."
sudo make && sudo make install

if [[ $? -eq 0 ]]; then
    echo "[+] YARA installation completed successfully!"
else
    echo "[-] Error: YARA installation failed."
fi

echo "[+] Cleaning up..."
cd ..
rm -rf yara* yara.tar.gz
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
