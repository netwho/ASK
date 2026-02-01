#!/bin/bash
# Quick install script for json.lua library for Wireshark

echo "Installing json.lua for Wireshark..."
echo ""

# Determine Wireshark plugins directory
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    PLUGINS_DIR="$HOME/.local/lib/wireshark/plugins"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    PLUGINS_DIR="$HOME/.local/lib/wireshark/plugins"
else
    echo "Unsupported OS. Please install manually - see INSTALL_JSON_LIBRARY.md"
    exit 1
fi

# Create plugins directory if it doesn't exist
mkdir -p "$PLUGINS_DIR"

# Download json.lua
echo "Downloading json.lua from GitHub..."
if command -v curl &> /dev/null; then
    curl -s -o "$PLUGINS_DIR/json.lua" https://raw.githubusercontent.com/rxi/json.lua/master/json.lua
elif command -v wget &> /dev/null; then
    wget -q -O "$PLUGINS_DIR/json.lua" https://raw.githubusercontent.com/rxi/json.lua/master/json.lua
else
    echo "Error: Neither curl nor wget found. Please install one of them."
    exit 1
fi

# Check if download was successful
if [ -f "$PLUGINS_DIR/json.lua" ]; then
    echo "✓ Successfully installed json.lua to: $PLUGINS_DIR/json.lua"
    echo ""
    echo "Next steps:"
    echo "1. Restart Wireshark"
    echo "2. The ASK (Analyst's Shark Knife) plugin will automatically use the JSON library"
    echo "3. Check Wireshark console for: 'JSON library successfully parsed response'"
    echo ""
    echo "This will improve parsing of:"
    echo "  - urlscan.io search results"
    echo "  - Complex JSON responses from all APIs"
    echo "  - Nested arrays and objects"
else
    echo "✗ Failed to download json.lua"
    echo "Please install manually - see INSTALL_JSON_LIBRARY.md"
    exit 1
fi
