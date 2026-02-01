# ASK Installation Guide - Linux

## Prerequisites

- **Linux distribution** (Ubuntu, Fedora, Arch, Debian, etc.)
- **Wireshark 4.2 or later**
- **curl** (usually pre-installed)
- **sudo** access (for installing packages)

## Installation Steps

### Step 1: Install the Plugin

**Using the installer script (Recommended):**
```bash
chmod +x install.sh
./install.sh
```

The installer will:
- Check Wireshark version
- Install `ask.lua` plugin
- Optionally install `scan_detector.lua` (Scan Detector plugin)
- Optionally install JSON library (if curl/wget available)
- Run API key setup script

**Manual installation:**
```bash
# Create Wireshark plugins directory if it doesn't exist
mkdir -p ~/.local/lib/wireshark/plugins

# Copy the plugin file
cp ask.lua ~/.local/lib/wireshark/plugins/

# Optionally install Scan Detector
cp ../Scan_Detector/scan_detector.lua ~/.local/lib/wireshark/plugins/

# Verify installation
ls -la ~/.local/lib/wireshark/plugins/ask.lua
ls -la ~/.local/lib/wireshark/plugins/scan_detector.lua  # if installed
```

### Step 2: Install Optional Tools

#### OpenSSL (for Certificate Validity Check)
```bash
# Debian/Ubuntu
sudo apt-get install openssl

# Fedora/RHEL/CentOS
sudo yum install openssl

# Arch Linux
sudo pacman -S openssl
```

#### dig (for DNS Analytics)
```bash
# Debian/Ubuntu
sudo apt-get install dnsutils

# Fedora/RHEL/CentOS
sudo yum install bind-utils

# Arch Linux
sudo pacman -S bind-tools
```

#### traceroute (for Traceroute feature)
```bash
# Debian/Ubuntu
sudo apt-get install traceroute

# Fedora/RHEL/CentOS
sudo yum install traceroute

# Arch Linux
sudo pacman -S traceroute
```

#### nmap (for Network Scanning)
```bash
# Debian/Ubuntu
sudo apt-get install nmap

# Fedora/RHEL/CentOS
sudo yum install nmap

# Arch Linux
sudo pacman -S nmap
```

**Note:** Nmap SYN scan and OS fingerprinting require root privileges. Run Wireshark with `sudo wireshark` if you need these features.

### Step 3: Configure API Keys

Run the setup script:
```bash
chmod +x setup_api_keys.sh
./setup_api_keys.sh
```

The script will:
- Create `~/.ask/` directory
- Prompt you for each API key
- Save keys securely with proper permissions (chmod 600)

### Step 4: Install JSON Library (Recommended)

The JSON library improves parsing performance for complex API responses. The installer will automatically check for `curl` or `wget` and offer to install it.

**If curl/wget is available:**
The installer will automatically download and install the JSON library when prompted.

**Manual installation:**
```bash
curl -o ~/.local/lib/wireshark/plugins/json.lua https://raw.githubusercontent.com/rxi/json.lua/master/json.lua
```

**If curl/wget is not available:**
1. Install curl using your package manager:
   - Debian/Ubuntu: `sudo apt-get install curl`
   - Fedora/RHEL/CentOS: `sudo yum install curl`
   - Arch Linux: `sudo pacman -S curl`
2. Then run the installer again, or manually download:
   ```bash
   curl -o ~/.local/lib/wireshark/plugins/json.lua https://raw.githubusercontent.com/rxi/json.lua/master/json.lua
   ```

**Why is the JSON library needed?**
- Improves parsing for urlscan.io search results
- Better handling of complex JSON responses from all APIs (AbuseIPDB, VirusTotal, Shodan, IPinfo, GreyNoise, OTX, Abuse.ch)
- More reliable parsing of nested arrays and objects

See `INSTALL_JSON_LIBRARY.md` for detailed instructions.

### Step 5: Restart Wireshark

Close and reopen Wireshark to load the plugin.

## Verification

1. Open Wireshark
2. Load any packet capture file
3. Right-click on an IP address field
4. You should see `IP Dest → ASK →` menu items

## Troubleshooting

### Plugin Not Loading
- Check Wireshark version: `Help → About Wireshark` (requires 4.2+)
- Check plugin location: `~/.local/lib/wireshark/plugins/ask.lua`
- Check Wireshark console for errors: `View → Internals → Lua`

### API Keys Not Working
- Verify API key files exist: `ls -la ~/.ask/*_API_KEY.txt`
- Check file permissions: `chmod 600 ~/.ask/*_API_KEY.txt`
- Verify API keys are correct (no extra spaces/newlines)

### Tools Not Found
- Ensure tools are in PATH: `which openssl`, `which dig`, `which nmap`
- Verify installation: `openssl version`, `dig -v`, `nmap --version`

### Permission Issues
- For nmap SYN scan: Run Wireshark with `sudo wireshark`
- For file permissions: Ensure `~/.ask/` directory has correct permissions

## Features Available on Linux

| Feature | Status | Notes |
|---------|--------|-------|
| DNS Registration Info (RDAP) | ✅ | No requirements |
| IP Registration Info (RDAP) | ✅ | No requirements |
| TLS Certificate Analysis | ✅ | No requirements |
| Certificate Transparency | ✅ | No requirements |
| Email Analysis | ✅ | No requirements |
| IP Reputation (AbuseIPDB) | ✅ | Requires API key |
| IP Reputation (VirusTotal) | ✅ | Requires API key |
| IP Intelligence (Shodan) | ✅ | Requires paid membership + API key |
| IP Intelligence (IPinfo) | ✅ | Requires API key |
| URL Reputation (urlscan.io) | ✅ | Works without key, better with key |
| Certificate Validity Check | ✅ | Requires openssl |
| DNS Analytics | ✅ | Requires dig (dnsutils/bind-utils) |
| Ping | ✅ | Pre-installed (iputils-ping) |
| Traceroute | ✅ | Requires installation |
| Nmap Scans | ✅ | Requires nmap installation |
| Scan Detector | ✅ | Optional plugin (scan_detector.lua) |

## Distribution-Specific Notes

### Ubuntu/Debian
- Package manager: `apt-get`
- Wireshark may require `sudo` for packet capture: `sudo wireshark`

### Fedora/RHEL/CentOS
- Package manager: `yum` or `dnf`
- SELinux may require additional configuration

### Arch Linux
- Package manager: `pacman`
- AUR packages available for some tools

## Next Steps

- See [Quick Start Guide](../../QUICKSTART.md) for usage examples
- Review [Feature Matrix](../../README.md#-feature-matrix) for capabilities
- Check [API Key Registration](../../README.md#-api-key-registration--free-tiers) for free tier limits
