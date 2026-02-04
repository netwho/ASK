# ASK Installation Guide - Windows

## Prerequisites

- **Windows 10 or later**
- **Wireshark 4.2 or later**
- **PowerShell 5.1+** (for setup script)

## Installation Steps

### Step 1: Install the Plugin

**Option A: Using Installer Script (Recommended)**
```cmd
.\install.bat
```

The batch file launcher (`install.bat`) automatically runs the PowerShell installer with the correct execution policy. This works even when running from network shares or when PowerShell scripts are blocked by policy.

> **Note:** If you prefer to run the PowerShell script directly:
> ```powershell
> powershell -ExecutionPolicy Bypass -File .\install.ps1
> ```

The installer will:
- Check Wireshark version
- Install `ask.lua` plugin
- Optionally install `scan_detector.lua` (Scan Detector plugin)
- Optionally install JSON library (if curl/Invoke-WebRequest available)
- Run API key setup script

**Option B: Using File Explorer**
1. Open File Explorer
2. Navigate to: `%APPDATA%\Wireshark\plugins\`
   - If the `plugins` folder doesn't exist, create it
3. Copy `ask.lua` to this folder
4. Optionally copy `Scan_Detector\scan_detector.lua` to this folder

**Option C: Using Command Prompt**
```cmd
mkdir %APPDATA%\Wireshark\plugins
copy ask.lua %APPDATA%\Wireshark\plugins\
copy ..\Scan_Detector\scan_detector.lua %APPDATA%\Wireshark\plugins\
```

**Option D: Using PowerShell**
```powershell
New-Item -ItemType Directory -Force -Path "$env:APPDATA\Wireshark\plugins"
Copy-Item ask.lua "$env:APPDATA\Wireshark\plugins\"
Copy-Item "..\Scan_Detector\scan_detector.lua" "$env:APPDATA\Wireshark\plugins\"
```

### Step 2: Install Optional Tools

#### OpenSSL (for Certificate Validity Check)
**Option 1: Git for Windows** (includes OpenSSL)
- Download: https://git-scm.com/download/win
- OpenSSL will be available after installation

**Option 2: Standalone OpenSSL**
- Download: https://slproweb.com/products/Win32OpenSSL.html
- Install and add to system PATH

**Option 3: Chocolatey**
```powershell
choco install openssl
```

#### dig (for DNS Analytics)
**Option 1: BIND Tools**
- Download: https://www.isc.org/download/
- Install BIND and add `dig.exe` to PATH

**Option 2: WSL (Windows Subsystem for Linux)**
- Install WSL and use Linux `dig` command

**Option 3: Chocolatey**
```powershell
choco install bind-toolsonly
```

#### nmap (for Network Scanning)
**Option 1: Official Installer**
- Download: https://nmap.org/download.html
- Install and add to system PATH

**Option 2: Chocolatey**
```powershell
choco install nmap
```

**Note:** Nmap SYN scan and OS fingerprinting require Administrator privileges. Run Wireshark as Administrator if you need these features.

### Step 3: Configure API Keys

**Option A: PowerShell Script (Recommended)**
```powershell
# Run PowerShell as Administrator (optional, for script execution)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\setup_api_keys.ps1
```

**Option B: Batch Script**
```cmd
setup_api_keys.bat
```

**Option C: Manual Setup**
1. Create directory: `%USERPROFILE%\.ask`
2. Create API key files:
   - `%USERPROFILE%\.ask\ABUSEIPDB_API_KEY.txt`
   - `%USERPROFILE%\.ask\VIRUSTOTAL_API_KEY.txt`
   - `%USERPROFILE%\.ask\SHODAN_API_KEY.txt`
   - `%USERPROFILE%\.ask\IPINFO_API_KEY.txt`
   - `%USERPROFILE%\.ask\URLSCAN_API_KEY.txt`
3. Add your API keys (one per file, no extra spaces)

### Step 4: Install JSON Library (Recommended)

The JSON library improves parsing performance for complex API responses. The installer will automatically check for `curl` or PowerShell's `Invoke-WebRequest` and offer to install it.

**If curl/Invoke-WebRequest is available:**
The installer will automatically download and install the JSON library when prompted.

**Manual installation:**
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/rxi/json.lua/master/json.lua" -OutFile "$env:APPDATA\Wireshark\plugins\json.lua"
```

**If curl is not available:**
1. curl is usually pre-installed on Windows 10+
2. If not available, download manually:
   - Download: https://raw.githubusercontent.com/rxi/json.lua/master/json.lua
   - Save to: `%APPDATA%\Wireshark\plugins\json.lua`

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
- Check plugin location: `%APPDATA%\Wireshark\plugins\ask.lua`
- Check Wireshark console for errors: `View → Internals → Lua`

### API Keys Not Working
- Verify API key files exist: `dir %USERPROFILE%\.ask\*_API_KEY.txt`
- Check file contents (no extra spaces/newlines)
- Ensure files are saved as plain text (not .txt.txt)

### Tools Not Found
- Verify tools are in PATH: `where openssl`, `where dig`, `where nmap`
- Add tools to system PATH if needed:
  1. Right-click "This PC" → Properties
  2. Advanced System Settings → Environment Variables
  3. Edit "Path" variable
  4. Add tool directories

### Permission Issues
- For nmap SYN scan: Run Wireshark as Administrator
- Right-click Wireshark → "Run as administrator"

### PowerShell Execution Policy
If scripts won't run, use the batch file launcher instead:
```cmd
.\install.bat
```

The batch file automatically bypasses execution policy restrictions. This is especially useful when:
- Running from network shares (UNC paths like `\\server\share\...`)
- Corporate environments with restricted PowerShell policies
- Scripts are not digitally signed

Alternatively, run PowerShell directly with bypass:
```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

## Features Available on Windows

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
| DNS Analytics | ⚠️ | Requires dig (BIND tools or WSL) |
| Ping | ✅ | Pre-installed |
| Traceroute | ✅ | Pre-installed (tracert) |
| Nmap Scans | ✅ | Requires nmap installation |
| Scan Detector | ✅ | Optional plugin (scan_detector.lua) |

## Windows-Specific Notes

### PATH Environment Variable
- GUI applications (like Wireshark) may not see PATH changes until restart
- Restart Wireshark after adding tools to PATH

### Administrator Privileges
- Some features (nmap SYN scan, OS fingerprinting) require Administrator privileges
- Run Wireshark as Administrator: Right-click → "Run as administrator"

### File Paths
- Use backslashes: `%USERPROFILE%\.ask\`
- Or forward slashes: `%USERPROFILE%/.ask/` (both work)

## Next Steps

- See [Quick Start Guide](../../QUICKSTART.md) for usage examples
- Review [Feature Matrix](../../README.md#-feature-matrix) for capabilities
- Check [API Key Registration](../../README.md#-api-key-registration--free-tiers) for free tier limits
