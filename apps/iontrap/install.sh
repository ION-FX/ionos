#!/bin/bash

APP_NAME="Ion Trap"
INSTALL_DIR="$HOME/.local/share/iontrap"
DESKTOP_FILE="$HOME/.local/share/applications/iontrap.desktop"
AUTOSTART_DIR="$HOME/.config/autostart"
AUTOSTART_FILE="$AUTOSTART_DIR/iontrap.desktop"

# File Names and URLs
SCRIPT_NAME="iontrap.py"
ICON_NAME="logo.png"
SCRIPT_URL="https://raw.githubusercontent.com/ION-FX/ionos/refs/heads/main/apps/iontrap/iontrap.py"
ICON_URL="https://raw.githubusercontent.com/ION-FX/ionos/refs/heads/main/apps/iontrap/logo.png"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Installing $APP_NAME for IonOS ===${NC}"

# 1. Install Dependencies (Fedora/Nobara specific)
echo -e "${GREEN}[1/4] Checking Dependencies...${NC}"

# Check for pip
if ! command -v pip &> /dev/null; then
    echo -e "${RED}Error: pip is not installed.${NC}"
    echo "Please install python3-pip (sudo dnf install python3-pip)"
    exit 1
fi

# We need sudo for dnf, but user might already have them.
if ! rpm -q python3-gobject &> /dev/null; then
    echo "Installing python3-gobject (requires sudo)..."
    sudo dnf install -y python3-gobject
fi

if ! rpm -q xdotool &> /dev/null; then
    echo "Installing xdotool (requires sudo)..."
    sudo dnf install -y xdotool
fi

# Install Python libs locally
echo "Installing Python libraries..."
pip install --upgrade pydbus psutil pynput PyQt6

# 2. Create Directory and Download Files
echo -e "${GREEN}[2/4] Downloading Files to $INSTALL_DIR...${NC}"
mkdir -p "$INSTALL_DIR"

# Download Script
echo "Downloading $SCRIPT_NAME..."
if curl -L -o "$INSTALL_DIR/$SCRIPT_NAME" "$SCRIPT_URL"; then
    echo "Script downloaded successfully."
else
    echo -e "${RED}Error: Failed to download script from GitHub.${NC}"
    exit 1
fi

# Download Icon
echo "Downloading $ICON_NAME..."
if curl -L -o "$INSTALL_DIR/$ICON_NAME" "$ICON_URL"; then
    echo "Icon downloaded successfully."
else
    echo -e "${RED}Warning: Failed to download icon. Proceeding without it.${NC}"
fi

# 3. Create .desktop File
echo -e "${GREEN}[3/4] Creating Desktop Entry...${NC}"
mkdir -p "$HOME/.local/share/applications"

cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Name=$APP_NAME
Comment=System-level Process Freezer
Exec=/usr/bin/python3 $INSTALL_DIR/$SCRIPT_NAME
Icon=$INSTALL_DIR/$ICON_NAME
Type=Application
Categories=System;Utility;
Terminal=false
X-GNOME-Autostart-enabled=true
EOF

# Make it executable just in case
chmod +x "$DESKTOP_FILE"

# 4. Set up Autostart
echo -e "${GREEN}[4/4] Enabling Autostart...${NC}"
mkdir -p "$AUTOSTART_DIR"
cp "$DESKTOP_FILE" "$AUTOSTART_FILE"

echo -e "${BLUE}=== Installation Complete! ===${NC}"
echo "Ion Trap has been installed."
echo "You can launch it from your application menu now."
echo "It will start automatically on your next login."
