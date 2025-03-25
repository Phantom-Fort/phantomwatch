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

# Install system dependencies
echo "[+] Installing system dependencies..."
sudo apt install -y sqlite3 curl wget python3-venv make gcc python3-pip > /dev/null 2>&1

# Ensure installation directory exists
echo "[+] Creating installation directories..."
sudo mkdir -p "$INSTALL_DIR" "$LOG_DIR" "$INSTALL_DIR/database"

# Ensure necessary permissions
echo "[+] Setting up permissions..."
sudo touch "$LOG_DIR/phantomwatch.log"
sudo chmod -R 755 "$INSTALL_DIR"
sudo chmod 644 "$LOG_DIR/phantomwatch.log"

# Change ownership to the current user
sudo chown -R $USER:$USER "$INSTALL_DIR"

# Copy PhantomWatch files
echo "[+] Copying PhantomWatch files..."
cp -r . "$INSTALL_DIR"

# Navigate to installation directory
cd "$INSTALL_DIR"

# Set up Python virtual environment
echo "[+] Setting up Python virtual environment..."
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

# Install dependencies
echo "[+] Installing Python dependencies..."
pip install -r requirements.txt

# Apply database schema with error handling
echo "[+] Setting up the database..."
if [[ -f "$SCHEMA_FILE" ]]; then
     if ! sqlite3 "$DB_PATH" < "$SCHEMA_FILE" > /dev/null 2> "$LOG_DIR/sqlite_error.log"; then
          echo "[-] Error: Failed to apply database schema. Check $LOG_DIR/sqlite_error.log for details."
          exit 1
     fi
else
     echo "[-] Error: Schema file not found."
     exit 1
fi

chmod 644 "$DB_PATH"

# Load environment variables from secrets.env
SECRETS_FILE="$INSTALL_DIR/config/secrets.env"

if [ ! -f "$SECRETS_FILE" ]; then
     echo "[+] Creating secrets.env file..."
     cat <<EOF > "$SECRETS_FILE"
# Add your environment variables here
# Example:
# export SECRET_KEY="your_secret_key"

EOF
fi

echo "[+] Loading environment variables from secrets.env..."
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
sudo rm -rf /usr/local/lib/python3*/dist-packages/phantomwatch
sudo cp -r "$INSTALL_DIR" /usr/local/lib/python3*/dist-packages/

# Create an executable script
echo "[+] Creating executable script..."
sudo tee "$BIN_PATH" > /dev/null <<EOF
#!/bin/bash
source "$VENV_DIR/bin/activate"
python3 "$INSTALL_DIR/cli/main.py" "\$@"
EOF

sudo chmod +x "$BIN_PATH"

echo "[+] Installation complete! You can now run PhantomWatch using the command: phantomwatch"
echo "[+] Please restart your shell to apply the changes."
