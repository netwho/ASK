# Quick Start Guide - ASK (Analyst's Shark Knife)

## 5-Minute Setup

### Step 1: Install Plugin

**Option A: Using Installer Scripts (Recommended)**
```bash
# macOS
./installers/macos/install.sh

# Linux
./installers/linux/install.sh
```

```cmd
# Windows (use the batch file - works on network shares and with restricted policies)
installers\windows\install.bat
```

> **Windows Note:** The `install.bat` wrapper automatically handles PowerShell execution policy restrictions. This is especially useful when running from network shares (UNC paths) or in corporate environments with restricted policies.

**Option B: Manual Installation**
```bash
# macOS/Linux
mkdir -p ~/.local/lib/wireshark/plugins
cp ask.lua ~/.local/lib/wireshark/plugins/

# Windows
mkdir %APPDATA%\Wireshark\plugins
copy ask.lua %APPDATA%\Wireshark\plugins\
```

### Step 1.5: Install JSON Library (Recommended)

**Why?** The plugin works without it, but a JSON library significantly improves parsing of complex responses (especially urlscan.io).

**Quick Install:**
```bash
# macOS/Linux
./install_json_library.sh

# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File install_json_library.ps1
```

**Manual Install:**
```bash
# macOS/Linux
curl -o ~/.local/lib/wireshark/plugins/json.lua https://raw.githubusercontent.com/rxi/json.lua/master/json.lua

# Windows: Download from https://raw.githubusercontent.com/rxi/json.lua/master/json.lua
# Save to %APPDATA%\Wireshark\plugins\json.lua
```

See [INSTALL_JSON_LIBRARY.md](INSTALL_JSON_LIBRARY.md) for detailed instructions.

### Step 2: Get API Keys (Optional but Recommended)

**AbuseIPDB (Free):**
1. Go to https://www.abuseipdb.com/api
2. Sign up for free account
3. Copy your API key

**urlscan.io (Free):**
1. Go to https://urlscan.io/user/signup
2. Sign up for free account
3. Copy your API key (optional but recommended)

**VirusTotal (Free):**
1. Go to https://www.virustotal.com/gui/join-us
2. Sign up for free account
3. Copy your API key from account settings

**Shodan (Paid Membership Required):**
1. Go to https://account.shodan.io/register
2. Sign up for account
3. **Upgrade to Membership** ($49 one-time) at https://account.shodan.io/billing
4. Copy your API key from account dashboard
5. **Note:** Free tier accounts cannot access IP host lookups

**AlienVault OTX (Free):**
1. Go to https://otx.alienvault.com
2. Sign up for free account
3. Copy your API key from account settings
4. **Note:** Free tier provides unlimited requests

**Abuse.ch (Free):**
1. Go to https://auth.abuse.ch
2. Sign up for free account
3. Copy your Auth-Key
4. **Note:** Free tier under fair use policy. Provides URLhaus (malware URLs) and ThreatFox (IOCs)

### Step 3: Configure API Keys

**Option A: Automated Setup Scripts (Easiest - Recommended)**

**macOS/Linux:**
```bash
chmod +x setup_api_keys.sh
./setup_api_keys.sh
```

**Windows (PowerShell):**
```powershell
powershell -ExecutionPolicy Bypass -File setup_api_keys.ps1
```

**Windows (Batch):**
```cmd
setup_api_keys.bat
```

The setup scripts will:
- Create the API key directory automatically
- Prompt you for each API key separately
- Save keys securely with proper permissions
- Show a summary of configured keys

**Option B: Manual File Creation**

**macOS/Linux:**
```bash
mkdir -p ~/.ask
echo "your_abuseipdb_key" > ~/.ask/ABUSEIPDB_API_KEY.txt
echo "your_virustotal_key" > ~/.ask/VIRUSTOTAL_API_KEY.txt
echo "your_shodan_key" > ~/.ask/SHODAN_API_KEY.txt
echo "your_ipinfo_key" > ~/.ask/IPINFO_API_KEY.txt
echo "your_urlscan_key" > ~/.ask/URLSCAN_API_KEY.txt
echo "your_otx_key" > ~/.ask/OTX_API_KEY.txt
echo "your_abusech_key" > ~/.ask/ABUSECH_API_KEY.txt
chmod 600 ~/.ask/*_API_KEY.txt
```

**Windows:**
```cmd
mkdir %USERPROFILE%\.ask
echo your_abuseipdb_key > %USERPROFILE%\.ask\ABUSEIPDB_API_KEY.txt
echo your_virustotal_key > %USERPROFILE%\.ask\VIRUSTOTAL_API_KEY.txt
echo your_shodan_key > %USERPROFILE%\.ask\SHODAN_API_KEY.txt
echo your_ipinfo_key > %USERPROFILE%\.ask\IPINFO_API_KEY.txt
echo your_urlscan_key > %USERPROFILE%\.ask\URLSCAN_API_KEY.txt
echo your_otx_key > %USERPROFILE%\.ask\OTX_API_KEY.txt
echo your_abusech_key > %USERPROFILE%\.ask\ABUSECH_API_KEY.txt
```

**Option C: Environment Variables**

**macOS/Linux:** Add to `~/.zshrc` or `~/.bashrc`:
```bash
export ABUSEIPDB_API_KEY="your_key_here"
export VIRUSTOTAL_API_KEY="your_key_here"
export SHODAN_API_KEY="your_key_here"
export URLSCAN_API_KEY="your_key_here"
```
**Note:** On macOS, GUI apps don't inherit shell env vars. Use Option A or B instead.

**Windows:** Set in System Environment Variables (see README.md for details)

### Step 4: Restart Wireshark

Close and reopen Wireshark to load the plugin.

### Step 5: Test It!

1. Open any packet capture file
2. Right-click on a packet field and navigate to ASK:
   - **IP address:** `IP Src/Dest → ASK → IP Reputation (AbuseIPDB)`
   - **DNS query:** `DNS → ASK → DNS Registration Info (RDAP)`
   - **TLS Certificate:** `TLS → ASK → Certificate Analysis`
   - **TLS SNI:** `TLS → ASK → Certificate Validity Check` or `Certificate Transparency`
   - **Email:** `SMTP → ASK → Email Analysis` or `IMF → ASK → Email Analysis`
3. View the results in the popup window

## What Works Without API Keys?

✅ **DNS Registration Info (RDAP)** - No API key needed  
   → `DNS → ASK → DNS Registration Info (RDAP)`

✅ **IP Registration Info (RDAP)** - No API key needed  
   → `IP Src/Dest → ASK → IP Registration Info (RDAP)`

✅ **TLS Certificate Analysis** - No API key needed  
   → `TLS → ASK → Certificate Analysis`

✅ **Certificate Validity Check** - No API key needed (uses OpenSSL)  
   → `TLS → ASK → Certificate Validity Check` or `HTTP → ASK → Certificate Validity Check`

✅ **Certificate Transparency** - No API key needed  
   → `DNS → ASK → Certificate Transparency` or `TLS → ASK → Certificate Transparency`

✅ **Email Analysis** - Basic analysis without API keys  
   → `SMTP → ASK → Email Analysis` or `IMF → ASK → Email Analysis`

✅ **IP Intelligence (GreyNoise)** - No API key needed (Community API)  
   → `IP Src/Dest → ASK → IP Intelligence (GreyNoise)`  
   → Identifies internet scanners vs legitimate services (50 searches/week limit)

❌ **IP Intelligence (AlienVault OTX)** - Requires API key (free tier: unlimited requests)  
   → `IP Src/Dest → ASK → IP Intelligence (OTX)`  
   → Community-driven threat intelligence with pulse data

❌ **IP Reputation (AbuseIPDB)** - Requires API key  
   → `IP Src/Dest → ASK → IP Reputation (AbuseIPDB)`

❌ **IP Reputation (VirusTotal)** - Requires API key  
   → `IP Src/Dest → ASK → IP Reputation (VirusTotal)`

❌ **IP Intelligence (Shodan)** - Requires paid membership ($49+) and API key  
   → `IP Src/Dest → ASK → IP Intelligence (Shodan)`

❌ **IP Intelligence (IPinfo)** - Requires API key (free tier: 50K requests/month)  
   → `IP Src/Dest → ASK → IP Intelligence (IPinfo)`

✅ **IP Intelligence (GreyNoise)** - No API key needed (Community API, 50 searches/week)  
   → `IP Src/Dest → ASK → IP Intelligence (GreyNoise)`

❌ **URL Reputation (urlscan.io)** - Works without key, but better with one  
   → `HTTP → ASK → URL Reputation (urlscan.io)`

❌ **URL Reputation (VirusTotal)** - Requires API key  
   → `HTTP → ASK → URL Reputation (VirusTotal)`

❌ **Domain Reputation (VirusTotal)** - Requires API key  
   → `DNS → ASK → Domain Reputation (VirusTotal)`

❌ **Domain Intelligence (AlienVault OTX)** - Requires API key (free tier: unlimited requests)  
   → `DNS → ASK → Domain Intelligence (OTX)`  
   → Community-driven threat intelligence with pulse data

❌ **URL Intelligence (AlienVault OTX)** - Requires API key (free tier: unlimited requests)  
   → `HTTP → ASK → URL Intelligence (OTX)`  
   → Community-driven threat intelligence with pulse data

❌ **URL Intelligence (URLhaus)** - Requires Auth-Key (free tier: fair use)  
   → `HTTP → ASK → URL Intelligence (URLhaus)`  
   → Malware URL detection and payload information

❌ **Host Intelligence (URLhaus)** - Requires Auth-Key (free tier: fair use)  
   → `IP Src/Dest → ASK → Host Intelligence (URLhaus)`  
   → Malware URLs observed on host

❌ **IOC Intelligence (ThreatFox)** - Requires Auth-Key (free tier: fair use)  
   → `IP Src/Dest → ASK → IOC Intelligence (ThreatFox)`  
   → `DNS → ASK → IOC Intelligence (ThreatFox)`  
   → `HTTP → ASK → IOC Intelligence (ThreatFox)`  
   → Botnet C&C detection and malware family identification

## Troubleshooting

**Plugin not showing up?**
- Check Wireshark version (needs 4.2+)
- Verify file is in correct plugins directory
- Check console: `Help → About Wireshark → Folders → Personal Lua Plugins`

**API errors?**
- Verify API keys are set correctly
- Check internet connectivity
- Review rate limits (see README.md)

**curl not found?**
- macOS: `brew install curl`
- Linux: `sudo apt-get install curl`
- Windows: Already included in Windows 10+

## Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Check [RECOMMENDATIONS.md](RECOMMENDATIONS.md) for future enhancements
- Explore all available menu options in Wireshark
