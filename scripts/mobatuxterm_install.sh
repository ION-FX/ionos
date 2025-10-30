#!/bin/bash

# --- MobaTuxTerm Standalone Installer ---
# This script downloads the app from GitHub, installs it to a permanent
# user directory, and sets up the KDE menu.
# It can be run from any directory.

echo "Starting MobaTuxTerm installation..."

# --- 1. Define All Paths ---

# GitHub Repo
REPO_URL="https://github.com/ION-FX/ionos.git"
# The sub-folder where MobaTuxTerm lives in the repo
REPO_APP_PATH="apps/mobatuxterm"

# Temporary location to download the repo
# Using $$ adds the script's Process ID to make the name unique
TMP_DIR="/tmp/mobatuxterm-install-$$"

# Permanent install location for the app files
# ~/.local/share is the standard for user-level apps
INSTALL_DIR="$HOME/.local/share/MobaTuxTerm"

# Paths for KDE integration
USER_APPS_DIR="$HOME/.local/share/applications"
USER_ICON_DIR="$HOME/.local/share/icons/hicolor/128x128/apps"
DESKTOP_FILE_PATH="$USER_APPS_DIR/mobatuxterm.desktop"

# --- 2. Check for Dependencies ---
if ! command -v git &> /dev/null; then
    echo "Error: git is not installed. Please install git first."
    exit 1
fi
if ! python3 -m pip --version &> /dev/null; then
     echo "Error: python3-pip is not installed. Please install it."
     exit 1
fi

# --- 3. Download App from GitHub ---
echo "Downloading application from GitHub..."
# Clone *only* the main branch, and *only* to a depth of 1 (shallow clone)
git clone --depth 1 "$REPO_URL" "$TMP_DIR"
if [ $? -ne 0 ]; then
    echo "Error: Failed to clone GitHub repository."
    exit 1
fi

# Set the source directory for our files
SRC_DIR="$TMP_DIR/$REPO_APP_PATH"

# --- 4. Install Python Dependencies ---
echo "Installing Python dependencies..."
REQS_PATH="$SRC_DIR/mobatuxtermfiles/requirements.txt"
if [ ! -f "$REQS_PATH" ]; then
    echo "Error: requirements.txt not found at $REQS_PATH. Aborting."
    rm -rf "$TMP_DIR"
    exit 1
fi
python3 -m pip install -r "$REQS_PATH"
if [ $? -ne 0 ]; then
    echo "Error: Failed to install Python dependencies."
    rm -rf "$TMP_DIR"
    exit 1
fi

# --- 5. Copy Application to Permanent Location ---
echo "Installing application to $INSTALL_DIR..."
# Clean out any old installation first
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# Copy the *entire contents* of the app folder to the new location
cp -r "$SRC_DIR"/* "$INSTALL_DIR/"
if [ $? -ne 0 ]; then
    echo "Error: Failed to copy application files."
    rm -rf "$TMP_DIR"
    exit 1
fi

# --- 6. Install Icon ---
echo "Installing icon..."
mkdir -p "$USER_ICON_DIR"
cp "$INSTALL_DIR/mobatuxtermfiles/ionos-logo.png" "$USER_ICON_DIR/mobatuxterm.png"

# --- 7. Make the permanent script executable ---
chmod +x "$INSTALL_DIR/mobatuxterm.py"

# --- 8. Create KDE Menu Entry ---
echo "Creating KDE menu entry..."
mkdir -p "$USER_APPS_DIR"

# This .desktop file now points to the permanent paths
cat > "$DESKTOP_FILE_PATH" << EOF
[Desktop Entry]
Name=MobaTuxTerm
Comment=SSH and SFTP Client for IonOS
Exec=python3 "$INSTALL_DIR/mobatuxterm.py"
Icon=mobatuxterm
Terminal=false
Type=Application
Categories=Development;Network;System;
EOF

# --- 9. Refresh System Caches ---
echo "Updating application and icon databases..."
kbuildsycoca5 --noincremental &> /dev/null
gtk-update-icon-cache -f -t "$HOME/.local/share/icons/hicolor" &> /dev/null || true

# --- 10. Clean Up ---
echo "Cleaning up temporary files..."
rm -rf "$TMP_DIR"

echo ""
echo "---------------------------------------------------------"
echo " MobaTuxTerm Installation Complete!"
echo " Installed to: $INSTALL_DIR"
echo " You can now check your 'Development' menu."
echo "---------------------------------------------------------"
