# Changelog

All notable changes to ASK (Analyst's Shark Knife) will be documented in this file.

## [0.2.7] - 2026-02-06

### Shodan Subscription Error Handling

#### Fixed
- **Shodan 401 Unauthorized Handling** - Improved error handling for Shodan API responses when queries exceed Community subscription limits
  - Plain text "401 Unauthorized" responses now display a helpful message instead of generic "Invalid Response Format" error
  - Clear explanation of Shodan Community Membership ($49 one-time) limitations
  - Lists what's included (basic IP lookups, 100 credits/month) vs. what requires higher tiers (advanced filters, bulk exports)
  - Provides actionable options: simplify query, upgrade subscription, use InternetDB API, or use other ASK features

#### Changed
- **Version** - Updated ASK plugin version to 0.2.7 in main and installer Lua files
- **User-Agent** - Updated all ASK User-Agent strings to `ASK-Wireshark-Plugin/0.2.7`
- **Installer Banners** - Updated installer version banners for macOS, Linux, and Windows to 0.2.7
- **Documentation** - Updated README version badge and version callouts to 0.2.7

## [0.2.6] - 2026-02-04

### Maintenance Release

#### Changed
- **Version** - Updated ASK plugin version to 0.2.6 in main and installer Lua files
- **User-Agent** - Updated all ASK User-Agent strings to `ASK-Wireshark-Plugin/0.2.6`
- **Installer Banners** - Updated installer version banners for macOS, Linux, and Windows to 0.2.6
- **Documentation** - Updated README version badge and version callouts to 0.2.6

#### Scan Detector
- **Version** - Updated Scan Detector plugin version to 0.1.1
- **Documentation** - Updated Scan Detector docs to reference v0.1.1

## [0.2.5] - 2026-02-03

### API Integration Enhancements

#### Added
- **SSLLabs API Integration** - SSL/TLS security analysis now uses SSLLabs API v3 (Qualys SSL Labs)
  - Industry-standard security grading (A+ to F)
  - Comprehensive vulnerability detection (Heartbleed, POODLE, FREAK, BEAST, Logjam, DROWN)
  - Protocol support analysis (TLS versions, cipher suites)
  - Forward secrecy detection
  - HSTS (HTTP Strict Transport Security) status
  - RC4 cipher support detection
  - Certificate chain validation
  - Detailed certificate information (subject, issuer, validity, SANs, fingerprints)
  - Free service, no API key required

#### Changed
- **Certificate Validity Check** renamed to **SSL/TLS Security Analysis** to reflect comprehensive capabilities
- **Build String** - Updated to "2026-02-03 ssllabs-integration"
- **Version** - Updated to 0.2.5 across all files and User-Agent strings

#### Removed
- **OpenSSL Dependency** - No longer requires OpenSSL binary for certificate checking
- **ssl-checker.io API** - Replaced with SSLLabs API for better security analysis

#### Technical Details
- SSLLabs API uses polling mechanism for comprehensive analysis (may take 60-120 seconds for first scan)
- Caching enabled by default (startNew=off, fromCache=on) to use recent scan results
- Automatic status polling with 2-second intervals, maximum 60 seconds
- Enhanced result formatting with grade-based recommendations
- Detailed vulnerability assessment display
- Link to full SSLLabs report for detailed analysis
- **Smart Fallback**: When SSLLabs is at capacity, automatically falls back to OpenSSL (if installed) for basic certificate checking
- User-friendly error messages with actionable recommendations when both methods unavailable

## [0.2.4] - 2026-02-03

### New Features

#### Added
- **ASK Documents Directory** - Auto-creates ~/Documents/ASK/ directory on plugin load for log storage
- **Daily Log Files** - Query results can be saved to daily logs (ASK-YYYY-MM-DD.log format)
- **Copy to Clipboard Button** - Result windows now include a button to copy results to clipboard
- **Save to Log Button** - Result windows now include a button to append results to daily log file
- **Platform-Specific Clipboard Support** - Automatic detection and use of pbcopy (macOS), xclip/xsel (Linux), or clip (Windows)
- **Log Entry Metadata** - Each log entry includes timestamp, query type, and target (IP/domain/URL)
- **Enhanced Result Windows** - 9 query types updated with Copy/Log functionality:
  - DNS RDAP, IP RDAP, AbuseIPDB, VirusTotal IP/Domain/URL, Shodan, IPinfo, urlscan.io

### Bug Fixes

#### Fixed
- **Shodan API Error Handling** - Major improvements to Shodan API error detection and handling:
  - Fixed issue where valid Shodan JSON responses were incorrectly flagged as errors
  - Fixed false positive HTML detection when JSON contains words like "cloud" in data fields
  - Added detection for HTML error pages (Microsoft Azure Web App, Cloudflare) before JSON parsing
  - HTML detection now only triggers on actual HTML tags (<!DOCTYPE, <html>, <head>, <body>) or non-JSON error messages
  - Improved handling of truncated JSON responses
  - Better validation that response looks like valid JSON before parsing
  - Simplified error recovery logic for more reliable operation
  - Enhanced error messages with better troubleshooting guidance
- **HTTP Response Processing** - Re-enabled `allow_error_json` option for Shodan to properly handle API responses that may contain error indicators but are actually valid data

#### Changed
- **Error Messages** - Improved Shodan error messages to be more descriptive and actionable
- **Build String** - Updated to "2026-02-03 logging-clipboard"
- **Version** - Updated to 0.2.4 across all files and User-Agent strings

#### Technical Details
- Removed overly complex error recovery logic that attempted to extract JSON from error messages
- Added early detection of HTML error pages (checks for DOCTYPE, html tags, Azure/Cloudflare indicators)
- Validates response format before JSON parsing (checks for { or [ start characters)
- Better logging for debugging Shodan API issues
- Clearer error messages guide users to alternative ASK features when Shodan is unavailable

## [0.2.3] - 2026-02-03

### Bug Fixes

#### Fixed
- **Shodan API Error Handling** - Fixed HTML detection to only check start of response
  - Resolved issue where HTML content embedded in JSON data was incorrectly flagged as error
  - HTML tags in scan results (e.g., `"html": "<!DOCTYPE..."`) no longer trigger false positives
  - Detection now uses `^` anchor to match only at response start

#### Changed
- **Build String** - Updated to "2026-02-03 shodan-error-fix"
- **Version** - Updated to 0.2.3

## [0.2.2] - 2026-01-29

### API Integration Enhancements

#### Added
- **ssl-checker.io API Integration** - Certificate validity checking now uses ssl-checker.io API as primary method (no API key required)
- **Cloudflare DNS over HTTPS (DoH)** - DNS Analytics now uses Cloudflare DoH API as primary method (no API key required)
- **Enhanced Certificate Information** - Certificate checks now include serial number, algorithm, SANs, SHA1 fingerprint, and HSTS status when using ssl-checker.io API
- **Cross-Platform DNS Support** - DNS Analytics works without local DNS tools when curl is available via Cloudflare DoH

#### Changed
- **Certificate Validity Check** - Now prioritizes ssl-checker.io API over OpenSSL (requires curl, no API key needed)
- **DNS Analytics** - Now prioritizes Cloudflare DoH over dig/nslookup (requires curl, no API key needed)
- **Feature Matrix** - Updated to reflect new API-based methods with fallback options
- **Documentation** - Updated README with new API integrations and their benefits

#### Fixed
- **Windows Certificate Checking** - Improved reliability with ssl-checker.io API fallback
- **DNS Tool Availability** - DNS Analytics no longer requires dig/nslookup when curl is available

## [0.2.1] - 2026-01-29

### Enhanced Installer and Integration

#### Added
- **Version Checking and Upgrade Detection** - Installers now detect existing installations and offer upgrades based on version comparison
- **Scan Detector Integration** - Scan Detector plugin is now part of ASK installer with optional installation prompt
- **Smart JSON Library Installation** - Automatic detection of curl/wget before offering JSON library installation
- **Improved Upgrade Flow** - Installers compare versions and file timestamps to determine if upgrade is needed
- **ssl-checker.io API Integration** - Certificate validity checking now uses ssl-checker.io API (no API key required) as primary method with OpenSSL fallback
- **Cloudflare DNS over HTTPS (DoH)** - DNS Analytics now uses Cloudflare DoH API (no API key required) as primary method with dig/nslookup fallback
- **Enhanced Certificate Information** - Certificate checks now include serial number, algorithm, SANs, SHA1 fingerprint, and HSTS status when using ssl-checker.io API
- **Cross-Platform DNS Support** - DNS Analytics works without local DNS tools when curl is available via Cloudflare DoH

#### Changed
- **Installer Scripts** - All installers (macOS, Linux, Windows) now check for existing installations
- **Version Reporting** - Updated to version 0.2.1 across all files
- **User-Agent Strings** - Updated to reflect version 0.2.1
- **Certificate Validity Check** - Now prioritizes ssl-checker.io API over OpenSSL (requires curl, no API key needed)
- **DNS Analytics** - Now prioritizes Cloudflare DoH over dig/nslookup (requires curl, no API key needed)
- **Feature Matrix** - Updated to reflect new API-based methods with fallback options

#### Fixed
- **Installation Experience** - Better handling of existing installations with clear upgrade prompts
- **JSON Library Dependencies** - Clearer instructions when download tools are missing
- **Windows Certificate Checking** - Improved reliability with ssl-checker.io API fallback
- **DNS Tool Availability** - DNS Analytics no longer requires dig/nslookup when curl is available

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
