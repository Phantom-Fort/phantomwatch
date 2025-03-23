#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

# Define installation directories
INSTALL_DIR="/opt/phantomwatch"
LOG_DIR="$INSTALL_DIR/logs"
VENV_DIR="$INSTALL_DIR/venv"
BIN_PATH="/usr/local/bin/phantomwatch"
DB_PATH="$INSTALL_DIR/database/phantomwatch.db"
SCHEMA_FILE="$INSTALL_DIR/database/schema.sql"

echo "[+] Installing PhantomWatch as a system package..."

# Ensure script is run with sudo
if [[ $EUID -ne 0 ]]; then
   echo "[-] Please run this script as root (sudo)." 
   exit 1
fi

# Install system dependencies
apt install -y sqlite3 curl wget python3-venv make gcc python3-pip > /dev/null 2>&1

# Ensure installation directory exists
mkdir -p "$INSTALL_DIR" "$LOG_DIR" "$INSTALL_DIR/database"

# Ensure necessary permissions
touch "$LOG_DIR/phantomwatch.log"
chmod -R 755 "$INSTALL_DIR"

# Copy PhantomWatch files
cp -r . "$INSTALL_DIR"

# Navigate to installation directory
cd "$INSTALL_DIR"

# Set up Python virtual environment
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

# Install dependencies
pip install -r requirements.txt > /dev/null 2>&1

# Apply database schema with error handling
echo "[+] Setting up the database..."

if [[ -f "$SCHEMA_FILE" ]]; then
    if ! sqlite3 "$DB_PATH" < "$SCHEMA_FILE" 2> "$LOG_DIR/sqlite_error.log"; then
        echo "[-] Error: Failed to apply database schema. Check $LOG_DIR/sqlite_error.log for details."
        exit 1
    fi
else
    echo "[-] Error: Database schema file not found at $SCHEMA_FILE."
    exit 1
fi

# Load environment variables from secrets.env
SECRETS_FILE="$INSTALL_DIR/config/secrets.env"

if [ ! -f "$SECRETS_FILE" ]; then
    cat <<EOF > "$SECRETS_FILE"
# Add your environment variables here
# Example:
# export SECRET_KEY="your_secret_key"
EOF
fi

if ! export $(grep -v '^#' "$SECRETS_FILE" | xargs) 2>/dev/null; then
    echo "[-] Error: Failed to load environment variables from secrets.env"
fi

# Persist environment variables in virtual environment
ACTIVATE_SCRIPT="$VENV_DIR/bin/activate"

echo "[+] Persisting environment variables..."
if [ -f "$ACTIVATE_SCRIPT" ]; then
    echo "source $SECRETS_FILE" >> "$ACTIVATE_SCRIPT"
else
    echo "[-] Error: Virtual environment activation script not found."
fi

# Install PhantomWatch as a package
echo "[+] Installing PhantomWatch as a package..."
rm -rf /usr/local/lib/python3*/dist-packages/phantomwatch
cp -r "$INSTALL_DIR" /usr/local/lib/python3*/dist-packages/

# Create an executable script
echo "[+] Creating executable script..."
tee "$BIN_PATH" > /dev/null <<EOF
#!/bin/bash
source "$VENV_DIR/bin/activate"
python3 "$INSTALL_DIR/cli/main.py" "\$@"
EOF

# Add execution permissions
chmod +x "$BIN_PATH"
chown -R $USER:$USER "$INSTALL_DIR"
chown $USER:$USER "$LOG_DIR/phantomwatch.log"
chmod 644 "$LOG_DIR/phantomwatch.log"
chmod 644 "$DB_PATH"


echo "[+] Installation complete! You can now run PhantomWatch using the command: phantomwatch"
echo "[+] Please restart your shell to apply the changes."
