#!/bin/bash

# --- MobaTuxTerm Installer Script ---
# This script installs MobaTuxTerm for the current user on a KDE system.

echo "Starting MobaTuxTerm installation..."

# --- 1. Define Paths ---

# Get the absolute path to the directory this script is in
# This is the root of the cloned 'mobatuxterm' app folder.
APP_DIR=$(cd "$(dirname "$0")" && pwd)

# Paths to the files, relative to this script
EXEC_PATH="$APP_DIR/mobatuxterm.py"
ICON_PATH="$APP_DIR/mobatuxtermfiles/ionos-logo.png"
REQS_PATH="$APP_DIR/mobatuxtermfiles/requirements.txt"

# Paths to the user's system folders
USER_APPS_DIR="$HOME/.local/share/applications"
USER_CONFIG_DIR="$HOME/.config/MobaTuxTerm"
DESKTOP_FILE_PATH="$USER_APPS_DIR/mobatuxterm.desktop"

# --- 2. Install Dependencies ---

echo "Installing Python dependencies (PyQt6, Paramiko, Cryptography...)"

# Install dependencies from the requirements.txt inside mobatuxtermfiles
python3 -m pip install -r "$REQS_PATH"

# Check if pip install was successful
if [ $? -ne 0 ]; then
    echo "Error: Failed to install Python dependencies. Please check pip."
    exit 1
fi

# --- 3. Create User Directories ---

echo "Creating system directories..."
# Create directory for the menu entry
mkdir -p "$USER_APPS_DIR"
# Create a config directory for session files
mkdir -p "$USER_CONFIG_DIR"

# --- 4. Make App Executable ---
chmod +x "$EXEC_PATH"

# --- 5. Create the KDE Menu Entry (.desktop file) ---

echo "Creating KDE desktop entry at $DESKTOP_FILE_PATH..."

# Create the .desktop file.
# Note that 'Exec' and 'Icon' point to the paths inside the
# folder where the user cloned the app.
cat > "$DESKTOP_FILE_PATH" << EOF
[Desktop Entry]
Name=MobaTuxTerm
Comment=SSH and SFTP Client for IonOS
Exec=python3 "$EXEC_PATH"
Icon=$ICON_PATH
Terminal=false
Type=Application
Categories=Development;Network;System;
EOF

# --- 6. Update KDE Menu ---
echo "Updating KDE application database..."
kbuildsycoca5 --noincremental &> /dev/null

echo ""
echo "---------------------------------------------------------"
echo " MobaTuxTerm Installation Complete!"
echo " Check your 'Development' menu (you may need to log out)."
echo "---------------------------------------------------------"
