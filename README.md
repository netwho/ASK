![ASK Logo](ask-logo.png)

# ASK (Analyst's Shark Knife)

[![Version](https://img.shields.io/badge/version-0.2.7-blue.svg)](CHANGELOG.md)
[![Status](https://img.shields.io/badge/status-initial%20public%20release-green.svg)](CHANGELOG.md)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](LICENSE)
[![Wireshark](https://img.shields.io/badge/Wireshark-4.2%2B-1679A7.svg)](https://www.wireshark.org/)
[![Lua](https://img.shields.io/badge/Lua-5.1%2B-000080.svg)](https://www.lua.org/)
[![macOS](https://img.shields.io/badge/macOS-10.14%2B-000000.svg?logo=apple)](installers/macos/)
[![Linux](https://img.shields.io/badge/Linux-Ubuntu%20|%20Fedora%20|%20Arch-FCC624.svg?logo=linux&logoColor=black)](installers/linux/)
[![Windows](https://img.shields.io/badge/Windows-10%2B-0078D6.svg?logo=windows)](installers/windows/)

A comprehensive Wireshark Lua plugin suite for security analytics and IOC (Indicators of Compromise) research. Provides real-time threat intelligence lookups directly from Wireshark's packet context menu.

> **✨ Version 0.2.7**: Improved Shodan error handling for Community subscription users! Now displays helpful messages about subscription limitations instead of generic errors, with clear options for resolving issues.

> **⚠️ Important**: Some features require external tools (nmap, dig, traceroute) and API keys. Please review the [Feature Matrix](#-feature-matrix) and check your platform's [installer documentation](installers/) before installation to ensure all dependencies are available.

## ✨ Features

- 🔍 **DNS Registration Info (RDAP)** - Modern RDAP lookups, no API key required
- 🌐 **IP Registration Data (RDAP)** - ARIN/RIPE/APNIC/LACNIC/AFRINIC registration info, IPv4 & IPv6
- 🛡️ **IP Reputation** - AbuseIPDB and VirusTotal integration
- 🔍 **IP Intelligence** - Shodan, IPinfo, GreyNoise, AlienVault OTX, and Abuse.ch (URLhaus/ThreatFox) integration with VPN/Proxy/Tor detection and scanner identification
- 🔗 **URL Reputation** - urlscan.io sandbox analysis, VirusTotal scanning, AlienVault OTX threat intelligence, and URLhaus malware detection
- 🌐 **Domain Reputation** - VirusTotal and AlienVault OTX domain analysis
- 🔐 **TLS Certificate Analysis** - Direct certificate inspection and Certificate Transparency logs
- 🔒 **SSL/TLS Security Analysis** - SSLLabs API integration (no API key required) 
- 📧 **Email Analysis** - SMTP/IMF email address analysis
- 📊 **DNS Analytics** - Cloudflare DNS over HTTPS (DoH) integration with dig/nslookup fallback for comprehensive DNS lookups (PTR, A, AAAA, MX, TXT, NS, SOA, CNAME)
- 🌐 **Network Diagnostics** - Ping and Traceroute tools
- 🔍 **Network Scanning** - Nmap integration (SYN scan, service scan, Vulners vulnerability scan)
- 🛡️ **Scan Detector** - Optional post-dissector plugin for real-time network scan detection (SYN, ACK, FIN, XMAS, NULL, UDP, ARP scans)

## 📸 Usage

Access the plugin from Wireshark's packet context menu:

```
Right-click on packet field → ASK → [Feature]
```

**Examples:**
- **IP address:** `IP Dest → ASK → IP Reputation (AbuseIPDB)`
- **DNS query:** `DNS → ASK → DNS Registration Info (RDAP)`
- **TLS Certificate:** `TLS → ASK → Certificate Analysis`
- **HTTP URL:** `HTTP → ASK → URL Reputation (urlscan.io)`

## 📷 Screenshots

### Context Menu
![ASK Context Menu](screenshots/screenshot-menu.png)

*Right-click on any packet field to access ASK features*

### IP Reputation Lookup
![IP Reputation](screenshots/screenshot-ip-reputation.png)

*View IP reputation scores from multiple threat intelligence sources*

### URL Analysis
![URL Reputation](screenshots/screenshot-url-reputation.png)

*Analyze URLs with urlscan.io sandbox results and VirusTotal scanning*

### Certificate Analysis
![Certificate Analysis](screenshots/screenshot-certificate-analysis.png)

*Inspect TLS certificates and check Certificate Transparency logs*

### Installer
![Installer](screenshots/screenshot-installer.png)

*Easy installation with version checking and upgrade detection*

## 🚀 Quick Start

### Installation

#### macOS
```bash
# See detailed instructions: installers/macos/README.md
cd installers/macos
chmod +x install.sh
./install.sh
```

The installer will:
- Install `ask.lua` plugin
- Optionally install `scan_detector.lua` (Scan Detector plugin)
- Optionally install JSON library (if curl/wget available)
- Run API key setup script

#### Linux
```bash
# See detailed instructions: installers/linux/README.md
cd installers/linux
chmod +x install.sh
./install.sh
```

The installer will:
- Install `ask.lua` plugin
- Optionally install `scan_detector.lua` (Scan Detector plugin)
- Optionally install JSON library (if curl/wget available)
- Run API key setup script

#### Windows
**Windows users:** Please follow the **[Windows Installation Guide](installers/windows/README.md)** for detailed step-by-step instructions.

```powershell
# Run installer
cd installers\windows
.\install.ps1
```

The installer will:
- Install `ask.lua` plugin
- Optionally install `scan_detector.lua` (Scan Detector plugin)
- Optionally install JSON library (if curl/Invoke-WebRequest available)
- Run API key setup script

## 📊 Feature Matrix

| Feature | No Requirements | API Key Required | External Tool Required | Free Tier Limits |
|---------|----------------|------------------|----------------------|------------------|
| **DNS Registration Info (RDAP)** | ✅ | ❌ | ❌ | Unlimited |
| **IP Registration Info (RDAP)** | ✅ | ❌ | ❌ | Unlimited |
| **TLS Certificate Analysis** | ✅ | ❌ | ❌ | Unlimited |
| **Quick Certificate Check** | ❌ | ❌ | ✅ openssl | Instant |
| **Certificate Validator** | ⚠️ Limited | ❌ | ✅ curl (SSLChecker.com) | Fast, fallback to OpenSSL |
| **SSL Security Analysis** | ⚠️ Limited | ❌ | ✅ curl (SSLLabs) | 60-120 sec first scan |
| **Certificate Transparency** | ✅ | ❌ | ❌ | Unlimited |
| **Email Analysis** (basic) | ✅ | ❌ | ❌ | Unlimited |
| **IP Reputation (AbuseIPDB)** | ❌ | ✅ | ❌ | 1,000/day |
| **IP Reputation (VirusTotal)** | ❌ | ✅ | ❌ | 4/min, 500/day |
| **IP Intelligence (Shodan)** | ❌ | ✅ (Paid) | ❌ | Requires $49+ membership |
| **IP Intelligence (IPinfo)** | ❌ | ✅ | ❌ | 50,000/month (Lite) |
| **IP Intelligence (GreyNoise)** | ✅ | ❌ | ❌ | 50 searches/week |
| **IP Intelligence (AlienVault OTX)** | ❌ | ✅ | ❌ | Unlimited (free tier) |
| **URL Reputation (urlscan.io)** | ⚠️ Limited | ✅ Recommended | ❌ | 100 scans/day, 10K searches/day |
| **URL Reputation (VirusTotal)** | ❌ | ✅ | ❌ | 4/min, 500/day |
| **URL Intelligence (AlienVault OTX)** | ❌ | ✅ | ❌ | Unlimited (free tier) |
| **URL Intelligence (URLhaus)** | ❌ | ✅ | ❌ | Fair use (free tier) |
| **Host Intelligence (URLhaus)** | ❌ | ✅ | ❌ | Fair use (free tier) |
| **IOC Intelligence (ThreatFox)** | ❌ | ✅ | ❌ | Fair use (free tier) |
| **Domain Reputation (VirusTotal)** | ❌ | ✅ | ❌ | 4/min, 500/day |
| **Domain Intelligence (AlienVault OTX)** | ❌ | ✅ | ❌ | Unlimited (free tier) |
| **DNS Analytics** | ⚠️ Limited | ❌ | ✅ curl (Cloudflare DoH) OR dig/nslookup | N/A |
| **Ping** | ❌ | ❌ | ✅ ping | N/A |
| **Traceroute** | ❌ | ❌ | ✅ traceroute | N/A |
| **Nmap Scans (SYN, Service, Vulners)** | ❌ | ❌ | ✅ nmap | N/A |
| **Scan Detector** (Optional Plugin) | ✅ | ❌ | ❌ | N/A |

### Legend
- ✅ **Works** - Feature is fully functional
- ⚠️ **Limited** - Feature works but requires an external tool (curl for API-based methods, or fallback tools like dig)
- ❌ **Not Available** - Feature requires the listed requirement

### Notes on Tool Requirements

**Certificate Checking (3 Options)**:
1. **Quick Certificate Check**: Direct OpenSSL connection. Instant, basic certificate info (subject, issuer, validity). Requires OpenSSL installed.
2. **Certificate Validator**: SSLChecker.com API via curl. Fast (seconds), more details than OpenSSL. Falls back to OpenSSL if API fails.
3. **SSL Security Analysis**: SSLLabs API via curl. Comprehensive security grading (A-F), vulnerability detection, protocol analysis. First scan 60-120 seconds, cached results instant. Falls back to OpenSSL if at capacity.

**Other Tools**:
- **DNS Analytics**: Uses Cloudflare DNS over HTTPS (DoH) via curl (no API key required). Falls back to dig/nslookup if DoH unavailable.
- **curl**: Usually pre-installed on macOS/Linux. Windows 10+ includes curl. Required for most API-based features.

## 🔑 API Key Registration & Free Tiers

### AbuseIPDB (Required for IP Reputation)
- **Registration:** https://www.abuseipdb.com/api
- **Free Tier:** 1,000 requests/day
- **What you get:** IP abuse confidence scores, total reports, distinct reporters, last reported date

### VirusTotal (Optional - Multiple Features)
- **Registration:** https://www.virustotal.com/gui/join-us
- **Free Tier:** 4 requests/minute, 500 requests/day
- **What you get:** 
  - IP reputation (70+ antivirus engines)
  - URL scanning and analysis
  - Domain reputation checking

### Shodan (Optional - IP Intelligence)
- **Registration:** https://account.shodan.io/register
- **Free Tier:** 100 queries/month (limited endpoints)
- **Paid Tier Required:** IP host lookups require $49 one-time minimum membership
- **What you get:** Comprehensive IP intelligence, open ports, services, banners, vulnerabilities

### IPinfo (Optional - IP Intelligence)
- **Registration:** https://ipinfo.io/signup
- **Free Tier:** 50,000 requests/month (Lite API - country/ASN only)
- **Paid Tiers:** Core/Plus/Business provide VPN/Proxy/Tor detection, hosting detection, abuse contacts
- **What you get:** 
  - Geolocation data
  - VPN/Proxy/Tor detection (paid tiers)
  - Hosting/datacenter detection
  - ASN information
  - Mobile carrier information (paid tiers)

### GreyNoise (Optional - IP Intelligence)
- **Registration:** Not required for Community API
- **Free Tier:** 50 searches per week (Community API - no API key needed)
- **What you get:** 
  - Internet scanner detection (identifies IPs scanning the internet)
  - RIOT dataset (legitimate business services)
  - IP classification (malicious, benign, unknown)
  - Reduces false positives from benign scanning activity
- **API:** https://api.greynoise.io/v3/community
- **Note:** No API key required for Community API. Perfect for identifying scanners vs legitimate services.

### urlscan.io (Optional - URL Analysis)
- **Registration:** https://urlscan.io/user/signup
- **Free Tier:** 100 scans/day, 10,000 searches/day
- **What you get:** 
  - Dynamic URL sandbox analysis
  - Security verdicts from multiple engines
  - Maliciousness scores
  - Resource analysis (domains, IPs, URLs contacted)

### Certificate Checking Services (No Registration Required)

**SSLLabs (SSL Security Analysis)**
- **Registration:** Not required - free service
- **API Key:** Not required  
- **Endpoint:** https://api.ssllabs.com/api/v3/analyze
- **What you get:**
  - Industry-standard security grading (A+ to F)
  - Comprehensive vulnerability detection (Heartbleed, POODLE, FREAK, BEAST, Logjam, DROWN)
  - Protocol and cipher suite analysis
  - Forward secrecy detection
  - HSTS status and configuration
  - Complete certificate chain information
- **Speed:** 60-120 seconds for first scan, instant for cached results
- **Note:** Falls back to OpenSSL if at capacity

**SSLChecker.com (Certificate Validator)**
- **Registration:** Not required - free service
- **API Key:** Not required
- **Endpoint:** https://www.sslchecker.com/certcheck
- **What you get:**
  - Certificate validity dates
  - Issuer and subject information
  - Serial number and signature algorithm
  - Subject Alternative Names (SANs)
  - Days until expiry
- **Speed:** Fast (seconds)
- **Note:** Falls back to OpenSSL if unavailable

### Cloudflare DNS over HTTPS (DNS Analytics - No Registration Required)
- **Registration:** Not required - free service
- **API Key:** Not required
- **Endpoint:** https://cloudflare-dns.com/dns-query
- **What you get:**
  - All DNS record types (A, AAAA, MX, NS, TXT, SOA, CNAME, PTR)
  - Reverse DNS lookups (PTR records)
  - Forward DNS lookups
  - Cross-platform support (no local DNS tools needed)
- **Note:** This is the primary method for DNS Analytics. Falls back to dig/nslookup if unavailable.

## 🛠️ External Tools

### Required Tools (for specific features)

| Tool | Feature(s) | Installation | Notes |
|------|-----------|--------------|-------|
| **curl** | SSL/TLS Security Analysis (SSLLabs API), DNS Analytics (Cloudflare DoH) | Usually pre-installed | Primary method for certificate checks and DNS lookups via APIs |
| **openssl** | SSL/TLS Security Analysis (fallback) | macOS: `brew install openssl`<br>Linux: `apt-get install openssl`<br>Windows: [Download](https://slproweb.com/products/Win32OpenSSL.html) | Fallback if SSLLabs API unavailable |
| **dig** or **nslookup** | DNS Analytics (fallback) | macOS: `brew install bind`<br>Linux: `apt-get install dnsutils`<br>Windows: nslookup pre-installed | Fallback if Cloudflare DoH unavailable |
| **ping** | Ping Host | Usually pre-installed | Network diagnostics |
| **traceroute** | Traceroute to Host | macOS: `brew install traceroute`<br>Linux: `apt-get install traceroute`<br>Windows: Pre-installed (tracert) | Network diagnostics |
| **nmap** | Network Scanning | macOS: `brew install nmap`<br>Linux: `apt-get install nmap`<br>Windows: [Download](https://nmap.org/download.html) | Network scanning (SYN, Service, Vulners scans) |

## 📋 Requirements

### Core Requirements
- **Wireshark 4.2+** (for `register_packet_menu` support)
- **curl** (for HTTP requests to APIs and Cloudflare DoH/SSLLabs API)
- **Lua JSON library** (recommended) - See [INSTALL_JSON_LIBRARY.md](INSTALL_JSON_LIBRARY.md)

### Feature-Specific Requirements
- **SSL/TLS Security Analysis**: Uses SSLLabs API (no API key required) via curl. Falls back to OpenSSL if API unavailable.
- **DNS Analytics**: Uses Cloudflare DNS over HTTPS (DoH) via curl (no API key required). Falls back to dig/nslookup if DoH unavailable.

### Optional Requirements
- API keys for enhanced features (see [Feature Matrix](#-feature-matrix))
- External tools for specific features (see [External Tools](#️-external-tools))

## 📖 Documentation

- **[Quick Start Guide](QUICKSTART.md)** - Get up and running in 5 minutes
- **[Platform-Specific Installation](installers/)** - Detailed setup for macOS, Linux, Windows
- **[JSON Library Installation](INSTALL_JSON_LIBRARY.md)** - Improve JSON parsing performance
- **[Scan Detector Documentation](Scan_Detector/)** - Network scan detection plugin
- **[Changelog](CHANGELOG.md)** - Version history and changes

## 🔧 Configuration

API keys are stored in:
- **macOS/Linux:** `~/.ask/`
- **Windows:** `%USERPROFILE%\.ask\`

The plugin automatically checks both `~/.ask/` and `~/.ioc_researcher/` for backward compatibility.

Use the provided setup scripts:
- **macOS/Linux:** `./setup_api_keys.sh`
- **Windows:** `setup_api_keys.bat` (recommended) or `powershell -ExecutionPolicy Bypass -File setup_api_keys.ps1`

> **Windows Note:** Use the `.bat` files when running from network shares (UNC paths like `\\server\share\...`) or in environments with restricted PowerShell execution policies. The batch files automatically bypass these restrictions.

## 📝 License

This project is licensed under the GNU General Public License v2.0 - see the [LICENSE](LICENSE) file for details.

---

With love for the Wireshark Community ❤️

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📧 Support

For issues, questions, or contributions, please use the GitHub Issues page.

## 🙏 Acknowledgments

- Wireshark team for the excellent packet analysis platform
- All API providers (AbuseIPDB, VirusTotal, Shodan, IPinfo, urlscan.io, AlienVault OTX, Abuse.ch) for their free tiers
- RDAP.org for providing free RDAP lookup services
- **ssl-checker.io** for free SSL certificate checking API (no registration required)
- **Cloudflare** for free DNS over HTTPS (DoH) service (no registration required)
- **rxi/json.lua** - Lightweight pure-Lua JSON library used for enhanced JSON parsing (MIT License) - https://github.com/rxi/json.lua
