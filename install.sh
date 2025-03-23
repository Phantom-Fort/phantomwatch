#!/bin/bash

echo "[+] Installing PhantomWatch as a system package..."

# Install system dependencies
sudo apt install -y -qq sqlite3 curl wget python3-venv make gcc python3-pip

# Set up Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install PhantomWatch as a package
pip install .

# Apply database schema
echo "[+] Setting up the database..."
mkdir -p ~/.phantomwatch/database
sqlite3 ~/.phantomwatch/database/phantomwatch.db < database/schema.sql

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

# Install PhantomWatch as a package
echo "[+] Installing PhantomWatch as a package..."
sudo rm -rf /usr/local/lib/python3*/dist-packages/phantomwatch
sudo cp -r phantomwatch /usr/local/lib/python3*/dist-packages/

# Create an executable script
echo "[+] Creating executable script..."
sudo tee /usr/local/bin/phantomwatch > /dev/null <<EOF
#!/bin/bash
python3 -m phantomwatch "\$@"
EOF

# Add execution permissions
sudo chmod +x /usr/local/bin/phantomwatch

echo "[+] Installation complete! You can now run PhantomWatch using the command: phantomwatch"
echo "[+] Please restart your shell to apply the changes."