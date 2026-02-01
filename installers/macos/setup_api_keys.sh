#!/bin/bash
# Setup script for ASK (Analyst's Shark Knife) API keys
# This creates the ~/.ask directory and helps you set up API key files

CONFIG_DIR="$HOME/.ask"

# Create config directory if it doesn't exist
mkdir -p "$CONFIG_DIR"

echo "ASK (Analyst's Shark Knife) API Key Setup"
echo "=========================================="
echo ""
echo "This script will help you set up API keys for ASK."
echo "API keys will be stored in: $CONFIG_DIR"
echo ""
echo "Press Enter to skip any API key you don't want to configure."
echo ""

# Function to prompt for API key
prompt_api_key() {
    local service_name=$1
    local file_name=$2
    local url=$3
    local required=$4  # "required" or "optional"
    
    echo "----------------------------------------"
    echo "[$service_name]"
    
    if [ -f "$CONFIG_DIR/$file_name" ]; then
        echo "✓ API key file already exists: $file_name"
        echo -n "Update this key? (y/N): "
        read -r update_choice
        if [ "$update_choice" != "y" ] && [ "$update_choice" != "Y" ]; then
            echo "Skipping $service_name..."
            echo ""
            return
        fi
    fi
    
    if [ "$required" = "required" ]; then
        echo "Get your free API key at: $url"
        echo -n "Enter $service_name API Key: "
    else
        echo "Optional - Get your free API key at: $url"
        echo -n "Enter $service_name API Key (or press Enter to skip): "
    fi
    
    read -r api_key
    
    if [ -n "$api_key" ]; then
        echo "$api_key" > "$CONFIG_DIR/$file_name"
        chmod 600 "$CONFIG_DIR/$file_name"
        echo "✓ $service_name API key saved"
    else
        if [ "$required" = "required" ]; then
            echo "⚠ Warning: $service_name API key is required but was not provided"
        else
            echo "Skipped $service_name (optional)"
        fi
    fi
    echo ""
}

# Prompt for each API key separately
prompt_api_key "AbuseIPDB" "ABUSEIPDB_API_KEY.txt" "https://www.abuseipdb.com/api" "required"

prompt_api_key "VirusTotal" "VIRUSTOTAL_API_KEY.txt" "https://www.virustotal.com/gui/join-us" "optional"

prompt_api_key "Shodan" "SHODAN_API_KEY.txt" "https://account.shodan.io/register" "optional"

prompt_api_key "IPinfo" "IPINFO_API_KEY.txt" "https://ipinfo.io/signup" "optional"

prompt_api_key "urlscan.io" "URLSCAN_API_KEY.txt" "https://urlscan.io/user/signup" "optional"

echo "========================================"
echo "Setup complete! API keys are stored in $CONFIG_DIR"
echo ""
echo "Summary of configured keys:"
if [ -f "$CONFIG_DIR/ABUSEIPDB_API_KEY.txt" ]; then
    echo "  ✓ AbuseIPDB"
else
    echo "  ✗ AbuseIPDB (not configured)"
fi
if [ -f "$CONFIG_DIR/VIRUSTOTAL_API_KEY.txt" ]; then
    echo "  ✓ VirusTotal"
else
    echo "  ✗ VirusTotal (optional)"
fi
if [ -f "$CONFIG_DIR/SHODAN_API_KEY.txt" ]; then
    echo "  ✓ Shodan"
else
    echo "  ✗ Shodan (optional)"
fi
if [ -f "$CONFIG_DIR/IPINFO_API_KEY.txt" ]; then
    echo "  ✓ IPinfo"
else
    echo "  ✗ IPinfo (optional)"
fi
if [ -f "$CONFIG_DIR/URLSCAN_API_KEY.txt" ]; then
    echo "  ✓ urlscan.io"
else
    echo "  ✗ urlscan.io (optional)"
fi
echo ""
echo "Restart Wireshark for changes to take effect."
