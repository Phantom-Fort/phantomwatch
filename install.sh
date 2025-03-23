#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

# Define installation directories
INSTALL_DIR="/opt/phantomwatch"
LOG_DIR="$INSTALL_DIR/logs"
VENV_DIR="$INSTALL_DIR/venv"
BIN_PATH="/usr/local/bin/phantomwatch"

echo "[+] Installing PhantomWatch as a system package..."

# Ensure script is run with sudo
if [[ $EUID -ne 0 ]]; then
   echo "[-] Please run this script as root (sudo)." 
   exit 1
fi

# Install system dependencies
sudo apt install -y sqlite3 curl wget python3-venv make gcc python3-pip > /dev/null 2>&1

# Ensure installation directory exists
mkdir -p "$INSTALL_DIR" "$LOG_DIR"

# Ensure necessary permissions for logs
touch "$LOG_DIR/phantomwatch.log"
chmod 644 "$LOG_DIR/phantomwatch.log"

# Copy PhantomWatch files
cp -r . "$INSTALL_DIR"

# Navigate to installation directory
cd "$INSTALL_DIR"

# Set up Python virtual environment
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

# Install PhantomWatch as a package
pip install -r requirements.txt > /dev/null 2>&1

# Apply database schema
echo "[+] Setting up the database..."
mkdir -p "$INSTALL_DIR/database"
sqlite3 "$INSTALL_DIR/database/phantomwatch.db" < database/schema.sql > /dev/null 2>&1

# Create and load environment variables from secrets.env
if [ ! -f "$INSTALL_DIR/config/secrets.env" ]; then
    cat <<EOF > "$INSTALL_DIR/config/secrets.env"
# Add your environment variables here
# Example:
# export SECRET_KEY="your_secret_key"
EOF
fi

if ! export $(grep -v '^#' "$INSTALL_DIR/config/secrets.env" | xargs) 2>/dev/null; then
    echo "[-] Error: Failed to load environment variables from secrets.env"
fi

# Ensure secrets.env is sourced in every new shell session
echo "[+] Persisting environment variables..."
if [[ "$SHELL" == */zsh ]]; then
    echo "source $INSTALL_DIR/config/secrets.env" >> ~/.zshrc
    source ~/.zshrc
elif [[ "$SHELL" == */bash ]]; then
    echo "source $INSTALL_DIR/config/secrets.env" >> ~/.bashrc
    source ~/.bashrc
else
    echo "[-] Warning: Unable to determine shell. Add 'source $INSTALL_DIR/config/secrets.env' manually to your shell profile."
fi

# Install PhantomWatch as a package
echo "[+] Installing PhantomWatch as a package..."
sudo rm -rf /usr/local/lib/python3*/dist-packages/phantomwatch
sudo cp -r "$INSTALL_DIR" /usr/local/lib/python3*/dist-packages/

# Create an executable script
echo "[+] Creating executable script..."
sudo tee "$BIN_PATH" > /dev/null <<EOF
#!/bin/bash
source "$VENV_DIR/bin/activate"
python3 "$INSTALL_DIR/cli/main.py" "\$@"
EOF

# Add execution permissions
sudo chmod +x "$BIN_PATH"

echo "[+] Installation complete! You can now run PhantomWatch using the command: phantomwatch"
echo "[+] Please restart your shell to apply the changes."
