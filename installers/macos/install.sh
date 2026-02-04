#!/bin/bash

# ASK (Analyst's Shark Knife) Installation Script for macOS
# Version: 0.2.5

set -e

echo "=========================================="
echo "ASK (Analyst's Shark Knife) Installer"
echo "Version 0.2.5 - macOS"
echo "=========================================="
echo ""

# Check if Wireshark is installed (PATH or standard app locations)
find_wireshark_bin() {
    local candidates=(
        "$(command -v wireshark 2>/dev/null)"
        "/Applications/Wireshark.app/Contents/MacOS/Wireshark"
        "/Applications/Wireshark.app/Contents/MacOS/Wireshark-qt"
        "/usr/local/bin/wireshark"
        "/opt/homebrew/bin/wireshark"
    )
    for c in "${candidates[@]}"; do
        if [ -n "$c" ] && [ -x "$c" ]; then
            echo "$c"
            return 0
        fi
    done

    # Fallback to Spotlight if available
    if command -v mdfind &> /dev/null; then
        local app_path
        app_path=$(mdfind "kMDItemCFBundleIdentifier == 'org.wireshark.Wireshark'" | head -n 1)
        if [ -n "$app_path" ] && [ -x "$app_path/Contents/MacOS/Wireshark" ]; then
            echo "$app_path/Contents/MacOS/Wireshark"
            return 0
        fi
    fi
    return 1
}

WIRESHARK_BIN="$(find_wireshark_bin || true)"
if [ -z "$WIRESHARK_BIN" ]; then
    echo "⚠️  Wireshark is not found in PATH or standard app locations."
    echo "   Please install Wireshark from https://www.wireshark.org/"
    exit 1
fi
echo "✓ Found Wireshark binary: $WIRESHARK_BIN"

# Get Wireshark version
WIRESHARK_VERSION=$("$WIRESHARK_BIN" -v 2>&1 | head -n 1 | grep -oE '[0-9]+\.[0-9]+' | head -n 1)
echo "✓ Found Wireshark version: $WIRESHARK_VERSION"

# Check version (requires 4.2+)
MAJOR=$(echo $WIRESHARK_VERSION | cut -d. -f1)
MINOR=$(echo $WIRESHARK_VERSION | cut -d. -f2)
if [ "$MAJOR" -lt 4 ] || ([ "$MAJOR" -eq 4 ] && [ "$MINOR" -lt 2 ]); then
    echo "⚠️  Wireshark 4.2+ is required. Found: $WIRESHARK_VERSION"
    exit 1
fi

# Create plugins directory
PLUGINS_DIR="$HOME/.local/lib/wireshark/plugins"
mkdir -p "$PLUGINS_DIR"
echo "✓ Created plugins directory: $PLUGINS_DIR"

# Get script and project directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Function to extract version from Lua file
extract_version() {
    local file="$1"
    if [ -f "$file" ]; then
        grep -oE 'version\s*=\s*"[0-9]+\.[0-9]+\.[0-9]+"' "$file" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1
    fi
}

# Function to compare versions (returns 0 if $1 >= $2, 1 otherwise)
version_compare() {
    local v1="$1"
    local v2="$2"
    if [ "$v1" = "$v2" ]; then
        return 0
    fi
    local IFS=.
    local i ver1=($v1) ver2=($v2)
    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++)); do
        ver1[i]=0
    done
    for ((i=0; i<${#ver1[@]}; i++)); do
        if [[ -z ${ver2[i]} ]]; then
            ver2[i]=0
        fi
        if ((10#${ver1[i]} > 10#${ver2[i]})); then
            return 0
        fi
        if ((10#${ver1[i]} < 10#${ver2[i]})); then
            return 1
        fi
    done
    return 0
}

# Check for existing installation and offer upgrade
INSTALLED_ASK="$PLUGINS_DIR/ask.lua"
SOURCE_ASK="$SCRIPT_DIR/ask.lua"

if [ -f "$INSTALLED_ASK" ]; then
    INSTALLED_VERSION=$(extract_version "$INSTALLED_ASK")
    SOURCE_VERSION=$(extract_version "$SOURCE_ASK")
    
    if [ -n "$INSTALLED_VERSION" ] && [ -n "$SOURCE_VERSION" ]; then
        # Compare versions
        if [ "$SOURCE_VERSION" != "$INSTALLED_VERSION" ]; then
            if version_compare "$SOURCE_VERSION" "$INSTALLED_VERSION"; then
                # Source version is newer or equal
                if version_compare "$INSTALLED_VERSION" "$SOURCE_VERSION"; then
                    # Versions are equal (both comparisons true)
                    echo "✓ Already installed version $INSTALLED_VERSION"
                    read -p "Reinstall anyway? (y/n) " -n 1 -r
                    echo
                    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                        echo "Skipping reinstallation."
                        SKIP_ASK_INSTALL=true
                    fi
                else
                    # Source is newer
                    echo ""
                    echo "📦 Existing installation detected:"
                    echo "   Installed version: $INSTALLED_VERSION"
                    echo "   Available version: $SOURCE_VERSION"
                    read -p "Upgrade to version $SOURCE_VERSION? (y/n) " -n 1 -r
                    echo
                    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                        echo "Skipping upgrade. Installation cancelled."
                        exit 0
                    fi
                fi
            else
                # Installed version is newer (shouldn't happen, but handle gracefully)
                echo "⚠️  Installed version ($INSTALLED_VERSION) is newer than source ($SOURCE_VERSION)"
                read -p "Downgrade to version $SOURCE_VERSION? (y/n) " -n 1 -r
                echo
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    echo "Skipping downgrade. Installation cancelled."
                    exit 0
                fi
            fi
        else
            # Versions are equal
            echo "✓ Already installed version $INSTALLED_VERSION"
            read -p "Reinstall anyway? (y/n) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                echo "Skipping reinstallation."
                SKIP_ASK_INSTALL=true
            fi
        fi
    else
        # Fallback to timestamp comparison
        if [ -f "$INSTALLED_ASK" ] && [ -f "$SOURCE_ASK" ]; then
            INSTALLED_TIME=$(stat -f %m "$INSTALLED_ASK" 2>/dev/null || echo "0")
            SOURCE_TIME=$(stat -f %m "$SOURCE_ASK" 2>/dev/null || echo "0")
            if [ "$SOURCE_TIME" -gt "$INSTALLED_TIME" ]; then
                echo ""
                echo "📦 Existing installation detected (newer source file found)"
                read -p "Upgrade installation? (y/n) " -n 1 -r
                echo
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    echo "Skipping upgrade. Installation cancelled."
                    exit 0
                fi
            fi
        fi
    fi
fi

# Install ask.lua
if [ "$SKIP_ASK_INSTALL" != "true" ]; then
    cp "$SOURCE_ASK" "$INSTALLED_ASK"
    if [ -n "$SOURCE_VERSION" ]; then
        echo "✓ Installed ask.lua version $SOURCE_VERSION"
    else
        echo "✓ Installed ask.lua"
    fi
fi

# Offer to install Scan Detector
echo ""
INSTALLED_SCAN_DETECTOR="$PLUGINS_DIR/scan_detector.lua"
SOURCE_SCAN_DETECTOR="$PROJECT_ROOT/Scan_Detector/scan_detector.lua"

if [ -f "$SOURCE_SCAN_DETECTOR" ]; then
    if [ -f "$INSTALLED_SCAN_DETECTOR" ]; then
        INSTALLED_SD_VERSION=$(extract_version "$INSTALLED_SCAN_DETECTOR")
        SOURCE_SD_VERSION=$(extract_version "$SOURCE_SCAN_DETECTOR")
        
        if [ -n "$INSTALLED_SD_VERSION" ] && [ -n "$SOURCE_SD_VERSION" ]; then
            if [ "$SOURCE_SD_VERSION" != "$INSTALLED_SD_VERSION" ]; then
                if version_compare "$SOURCE_SD_VERSION" "$INSTALLED_SD_VERSION"; then
                    if version_compare "$INSTALLED_SD_VERSION" "$SOURCE_SD_VERSION"; then
                        # Versions are equal
                        echo "✓ Scan Detector already installed (version $INSTALLED_SD_VERSION)"
                        read -p "Reinstall Scan Detector? (y/n) " -n 1 -r
                        echo
                        if [[ $REPLY =~ ^[Yy]$ ]]; then
                            cp "$SOURCE_SCAN_DETECTOR" "$INSTALLED_SCAN_DETECTOR"
                            echo "✓ Reinstalled scan_detector.lua"
                        fi
                    else
                        # Source is newer
                        echo "📦 Scan Detector already installed:"
                        echo "   Installed version: $INSTALLED_SD_VERSION"
                        echo "   Available version: $SOURCE_SD_VERSION"
                        read -p "Upgrade Scan Detector to version $SOURCE_SD_VERSION? (y/n) " -n 1 -r
                        echo
                        if [[ $REPLY =~ ^[Yy]$ ]]; then
                            cp "$SOURCE_SCAN_DETECTOR" "$INSTALLED_SCAN_DETECTOR"
                            echo "✓ Upgraded scan_detector.lua to version $SOURCE_SD_VERSION"
                        else
                            echo "Skipping Scan Detector upgrade."
                        fi
                    fi
                else
                    # Installed is newer
                    echo "⚠️  Installed Scan Detector ($INSTALLED_SD_VERSION) is newer than source ($SOURCE_SD_VERSION)"
                    read -p "Downgrade Scan Detector? (y/n) " -n 1 -r
                    echo
                    if [[ $REPLY =~ ^[Yy]$ ]]; then
                        cp "$SOURCE_SCAN_DETECTOR" "$INSTALLED_SCAN_DETECTOR"
                        echo "✓ Downgraded scan_detector.lua to version $SOURCE_SD_VERSION"
                    fi
                fi
            else
                # Versions are equal
                echo "✓ Scan Detector already installed (version $INSTALLED_SD_VERSION)"
                read -p "Reinstall Scan Detector? (y/n) " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    cp "$SOURCE_SCAN_DETECTOR" "$INSTALLED_SCAN_DETECTOR"
                    echo "✓ Reinstalled scan_detector.lua"
                fi
            fi
        else
            # Fallback to timestamp comparison
            INSTALLED_SD_TIME=$(stat -f %m "$INSTALLED_SCAN_DETECTOR" 2>/dev/null || echo "0")
            SOURCE_SD_TIME=$(stat -f %m "$SOURCE_SCAN_DETECTOR" 2>/dev/null || echo "0")
            if [ "$SOURCE_SD_TIME" -gt "$INSTALLED_SD_TIME" ]; then
                echo "📦 Scan Detector newer version available"
                read -p "Upgrade Scan Detector? (y/n) " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    cp "$SOURCE_SCAN_DETECTOR" "$INSTALLED_SCAN_DETECTOR"
                    echo "✓ Upgraded scan_detector.lua"
                fi
            else
                read -p "Install Scan Detector plugin? (y/n) " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    cp "$SOURCE_SCAN_DETECTOR" "$INSTALLED_SCAN_DETECTOR"
                    echo "✓ Installed scan_detector.lua"
                fi
            fi
        fi
    else
        read -p "Install Scan Detector plugin? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            cp "$SOURCE_SCAN_DETECTOR" "$INSTALLED_SCAN_DETECTOR"
            SOURCE_SD_VERSION=$(extract_version "$SOURCE_SCAN_DETECTOR")
            if [ -n "$SOURCE_SD_VERSION" ]; then
                echo "✓ Installed scan_detector.lua version $SOURCE_SD_VERSION"
            else
                echo "✓ Installed scan_detector.lua"
            fi
        fi
    fi
else
    echo "⚠️  scan_detector.lua not found in Scan_Detector directory"
fi

# Comprehensive dependency check
echo ""
echo "=========================================="
echo "Dependency Check - External Tools"
echo "=========================================="
echo ""
echo "Checking for external tools required by ASK features..."
echo ""

# Function to get tool purpose (Bash 3.2 compatible - no associative arrays)
get_tool_purpose() {
    case "$1" in
        openssl) echo "Certificate Validity Check" ;;
        nmap) echo "Network Scanning (SYN Scan, Service Scan, Vulners Scan)" ;;
        ping) echo "Ping feature" ;;
        traceroute) echo "Traceroute feature" ;;
        dig) echo "DNS Analytics (preferred)" ;;
        nslookup) echo "DNS Analytics (fallback)" ;;
        curl) echo "API requests (all threat intelligence APIs)" ;;
        *) echo "Unknown tool" ;;
    esac
}

# Define list of dependencies (Bash 3.2 compatible)
DEPENDENCIES="openssl nmap ping traceroute dig nslookup curl"

# Track missing dependencies
MISSING_DEPS=()
AVAILABLE_DEPS=()

# Check each dependency
for tool in $DEPENDENCIES; do
    if command -v "$tool" &> /dev/null; then
        echo "[+] $tool - Found"
        echo "    Purpose: $(get_tool_purpose "$tool")"
        AVAILABLE_DEPS+=("$tool")
    else
        echo "[!] $tool - NOT FOUND"
        echo "    Purpose: $(get_tool_purpose "$tool")"
        MISSING_DEPS+=("$tool")
    fi
done

# Show installation instructions for missing dependencies
if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo ""
    echo "=========================================="
    echo "Installation Instructions for Missing Tools"
    echo "=========================================="
    echo ""
    
    for tool in "${MISSING_DEPS[@]}"; do
        case "$tool" in
            openssl)
                echo "[!] OpenSSL - Required for Certificate Validity Check"
                echo "    Install: brew install openssl"
                echo "    Download: https://formulae.brew.sh/formula/openssl"
                echo "    Note: macOS includes OpenSSL but it may be outdated"
                ;;
            nmap)
                echo "[!] Nmap - Required for Network Scanning features"
                echo "    Install: brew install nmap"
                echo "    Download: https://formulae.brew.sh/formula/nmap"
                echo "    Website: https://nmap.org/"
                echo "    Note: Some scans require administrator privileges"
                ;;
            ping)
                echo "[!] Ping - Required for Ping feature"
                echo "    Status: Usually pre-installed on macOS"
                echo "    If missing, ping is part of macOS system tools"
                ;;
            traceroute)
                echo "[!] Traceroute - Required for Traceroute feature"
                echo "    Install: brew install traceroute"
                echo "    Download: https://formulae.brew.sh/formula/traceroute"
                echo "    Alternative: sudo port install traceroute (MacPorts)"
                ;;
            dig)
                echo "[!] Dig - Required for DNS Analytics (preferred tool)"
                echo "    Install: brew install bind"
                echo "    Download: https://formulae.brew.sh/formula/bind"
                echo "    Note: Includes dig, nslookup, and other DNS tools"
                ;;
            nslookup)
                echo "[!] Nslookup - Required for DNS Analytics (fallback)"
                echo "    Install: brew install bind"
                echo "    Download: https://formulae.brew.sh/formula/bind"
                echo "    Note: Usually included with bind package"
                ;;
            curl)
                echo "[!] Curl - Required for all API requests"
                echo "    Install: brew install curl"
                echo "    Download: https://formulae.brew.sh/formula/curl"
                echo "    Website: https://curl.se/"
                echo "    Note: macOS includes curl but Homebrew version is recommended"
                ;;
        esac
        echo ""
    done
    
    echo "After installing missing tools, restart Wireshark for changes to take effect."
    echo ""
    
    # Show feature availability summary
    echo "=========================================="
    echo "Feature Availability Summary"
    echo "=========================================="
    echo ""
    echo "Based on installed tools, the following features are available:"
    echo ""
    
    if [[ " ${AVAILABLE_DEPS[@]} " =~ " curl " ]]; then
        echo "[+] API-based Features: Available"
        echo "    - IP Reputation (AbuseIPDB, VirusTotal)"
        echo "    - IP Intelligence (Shodan, IPinfo, GreyNoise)"
        echo "    - Threat Intelligence (AlienVault OTX, Abuse.ch)"
        echo "    - URL Analysis (urlscan.io, VirusTotal)"
        echo "    - Certificate Transparency (crt.sh)"
    else
        echo "[!] API-based Features: UNAVAILABLE (curl required)"
    fi
    
    if [[ " ${AVAILABLE_DEPS[@]} " =~ " openssl " ]]; then
        echo "[+] Certificate Validity Check: Available"
    else
        echo "[!] Certificate Validity Check: UNAVAILABLE (openssl required)"
    fi
    
    if [[ " ${AVAILABLE_DEPS[@]} " =~ " dig " ]] || [[ " ${AVAILABLE_DEPS[@]} " =~ " nslookup " ]]; then
        echo "[+] DNS Analytics: Available"
    else
        echo "[!] DNS Analytics: UNAVAILABLE (dig or nslookup required)"
    fi
    
    if [[ " ${AVAILABLE_DEPS[@]} " =~ " ping " ]]; then
        echo "[+] Ping: Available"
    else
        echo "[!] Ping: UNAVAILABLE (ping required)"
    fi
    
    if [[ " ${AVAILABLE_DEPS[@]} " =~ " traceroute " ]]; then
        echo "[+] Traceroute: Available"
    else
        echo "[!] Traceroute: UNAVAILABLE (traceroute required)"
    fi
    
    if [[ " ${AVAILABLE_DEPS[@]} " =~ " nmap " ]]; then
        echo "[+] Network Scanning (Nmap): Available"
        echo "    - SYN Scan"
        echo "    - Service Scan"
        echo "    - Vulners Vulnerability Scan"
    else
        echo "[!] Network Scanning (Nmap): UNAVAILABLE (nmap required)"
    fi
    
    echo ""
else
    echo ""
    echo "[+] All external tools are available!"
    echo ""
    echo "All ASK features are fully functional:"
    echo "  - API-based threat intelligence lookups"
    echo "  - Certificate Validity Check"
    echo "  - DNS Analytics"
    echo "  - Network diagnostics (Ping, Traceroute)"
    echo "  - Network scanning (Nmap)"
    echo ""
fi

# Offer to install JSON library (check for curl/wget first)
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📚 JSON Library Installation (Recommended)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
HAS_DOWNLOAD_TOOL=false
if command -v curl &> /dev/null; then
    HAS_DOWNLOAD_TOOL=true
    DOWNLOAD_TOOL="curl"
elif command -v wget &> /dev/null; then
    HAS_DOWNLOAD_TOOL=true
    DOWNLOAD_TOOL="wget"
fi

if [ "$HAS_DOWNLOAD_TOOL" = true ]; then
    echo "The JSON library significantly improves parsing performance for:"
    echo "  • urlscan.io search results"
    echo "  • Complex JSON responses from all APIs"
    echo "  • Nested arrays and objects"
    echo ""
    read -p "Install JSON library? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        JSON_URL="https://raw.githubusercontent.com/rxi/json.lua/master/json.lua"
        if [ "$DOWNLOAD_TOOL" = "curl" ]; then
            curl -sSL "$JSON_URL" -o "$PLUGINS_DIR/json.lua"
        else
            wget -q -O "$PLUGINS_DIR/json.lua" "$JSON_URL"
        fi
        if [ -f "$PLUGINS_DIR/json.lua" ]; then
            echo "✓ Installed json.lua"
            echo ""
            echo "The JSON library improves parsing for:"
            echo "  - urlscan.io search results"
            echo "  - Complex JSON responses from all APIs (AbuseIPDB, VirusTotal, Shodan, etc.)"
            echo "  - Nested arrays and objects"
        else
            echo "⚠️  Failed to download json.lua"
        fi
    fi
else
    echo "⚠️  curl or wget not found - cannot auto-install JSON library"
    echo ""
    echo "The JSON library improves parsing performance for:"
    echo "  - urlscan.io search results"
    echo "  - Complex JSON responses from all APIs (AbuseIPDB, VirusTotal, Shodan, IPinfo, GreyNoise, OTX, Abuse.ch)"
    echo "  - Nested arrays and objects"
    echo ""
    echo "To install manually:"
    echo "1. Install curl: brew install curl"
    echo "2. Run: curl -o $PLUGINS_DIR/json.lua https://raw.githubusercontent.com/rxi/json.lua/master/json.lua"
    echo "   OR download from: https://raw.githubusercontent.com/rxi/json.lua/master/json.lua"
    echo "   Save to: $PLUGINS_DIR/json.lua"
    echo ""
    echo "See INSTALL_JSON_LIBRARY.md for detailed instructions."
fi

# Offer to run API key setup
echo ""
read -p "Run API key setup script? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if [ -f "$SCRIPT_DIR/setup_api_keys.sh" ]; then
        chmod +x "$SCRIPT_DIR/setup_api_keys.sh"
        "$SCRIPT_DIR/setup_api_keys.sh"
    else
        echo "⚠️  setup_api_keys.sh not found in installer directory"
    fi
fi

echo ""
echo "=========================================="
echo "Installation complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Restart Wireshark to load the plugin"
echo "2. Right-click on a packet field → ASK → [Feature]"
echo ""
echo "For more information, see:"
echo "- README.md in this directory"
echo "- https://github.com/netwho/ask"
echo ""
