# Changelog

All notable changes to ASK (Analyst's Shark Knife) will be documented in this file.

## [0.2.1] - 2026-01-29

### Enhanced Installer and Integration

#### Added
- **Version Checking and Upgrade Detection** - Installers now detect existing installations and offer upgrades based on version comparison
- **Scan Detector Integration** - Scan Detector plugin is now part of ASK installer with optional installation prompt
- **Smart JSON Library Installation** - Automatic detection of curl/wget before offering JSON library installation
- **Improved Upgrade Flow** - Installers compare versions and file timestamps to determine if upgrade is needed

#### Changed
- **Installer Scripts** - All installers (macOS, Linux, Windows) now check for existing installations
- **Version Reporting** - Updated to version 0.2.1 across all files
- **User-Agent Strings** - Updated to reflect version 0.2.1

#### Fixed
- **Installation Experience** - Better handling of existing installations with clear upgrade prompts
- **JSON Library Dependencies** - Clearer instructions when download tools are missing

## [0.2.0] - 2025-01-29

### Initial Public Release

#### Added
- **DNS Registration Info (RDAP)** - Modern RDAP lookups for domain registration information
- **IP Registration Info (RDAP)** - ARIN/RIPE/APNIC/LACNIC/AFRINIC IP registration data for IPv4 and IPv6
- **IP Reputation (AbuseIPDB)** - Abuse confidence scores and reporting data
- **IP Reputation (VirusTotal)** - Multi-engine IP reputation checking
- **IP Intelligence (Shodan)** - Comprehensive IP address intelligence (requires paid membership)
- **IP Intelligence (IPinfo)** - IP intelligence with VPN/Proxy/Tor detection
- **URL Reputation (urlscan.io)** - Dynamic URL sandbox analysis
- **URL Reputation (VirusTotal)** - Multi-engine URL scanning
- **Domain Reputation (VirusTotal)** - Domain reputation checking
- **TLS Certificate Analysis** - Direct certificate inspection from TLS handshakes
- **Certificate Validity Check** - Fast OpenSSL-based certificate validation
- **Certificate Transparency** - Search CT logs via crt.sh
- **Email Analysis** - SMTP/IMF email address analysis with domain reputation
- **DNS Analytics** - Comprehensive DNS lookups (PTR, A, AAAA, MX, TXT, NS, SOA, CNAME)
- **Network Diagnostics** - Ping and Traceroute tools
- **Network Scanning** - Nmap integration (SYN scan, service scan, OS fingerprinting)
- **RFC 1918 Private IP Detection** - Automatic detection and informative messages for private addresses
- **API Key Management** - File-based and environment variable support
- **Caching** - In-memory cache for API responses
- **Platform Support** - macOS, Linux, and Windows

#### Features
- Automatic root privilege detection for nmap scans
- Fallback to TCP connect scan when SYN scan requires root
- Backward compatibility with `.ioc_researcher` directory
- Comprehensive error handling and user guidance
- Platform-specific tool detection and installation instructions

#### Documentation
- Complete README with feature matrix
- Platform-specific installation guides
- Quick start guide
- JSON library installation guide
