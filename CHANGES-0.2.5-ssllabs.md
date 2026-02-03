# ASK Version 0.2.5 Release Notes

**Release Date**: 2026-02-03  
**Build**: ssllabs-integration

## Overview

Version 0.2.5 replaces the certificate validity check with comprehensive SSL/TLS security analysis using the SSLLabs API. This provides industry-standard security grading, vulnerability detection, and detailed TLS configuration analysis—all without requiring OpenSSL to be installed.

## What's New

### SSLLabs API Integration

The **Certificate Validity Check** feature has been completely redesigned and renamed to **SSL/TLS Security Analysis**. It now uses the Qualys SSL Labs API v3 to provide comprehensive security analysis.

#### Key Features

1. **Security Grading (A+ to F)**
   - Industry-standard SSL/TLS security rating
   - Visual grade indicators (✓ for A/A+, ⚠ for B/C/D, ⚠⚠ for F/T)
   - Grade-specific recommendations for improvement

2. **Vulnerability Detection**
   - Heartbleed
   - POODLE
   - FREAK
   - BEAST
   - Logjam
   - DROWN
   - Clear indicators for vulnerable vs protected systems

3. **Protocol & Cipher Analysis**
   - Supported TLS/SSL protocol versions
   - Cipher suite configuration
   - Forward secrecy status
   - RC4 cipher support detection

4. **Certificate Information**
   - Subject and Issuer details
   - Validity period with expiration warnings
   - Days until expiry calculation
   - Subject Alternative Names (SANs)
   - Certificate fingerprints (SHA-1, SHA-256)
   - Signature algorithm

5. **Security Features**
   - HSTS (HTTP Strict Transport Security) status
   - HSTS max-age configuration
   - Forward secrecy implementation
   - Insecure cipher warnings

## Improvements Over Previous Version

### Before (v0.2.4)
- Used ssl-checker.io API with OpenSSL fallback
- Basic certificate validity checking
- Limited security analysis
- Required OpenSSL installation for fallback

### After (v0.2.5)
- Uses industry-standard SSLLabs API v3
- Comprehensive SSL/TLS security analysis with A-F grading
- Vulnerability detection for major SSL/TLS vulnerabilities
- Protocol and cipher suite analysis
- **No OpenSSL dependency required**
- Free service, no API key needed

## How It Works

1. **Initial Request**: When you check a certificate, ASK queries the SSLLabs API
2. **Caching**: By default, uses cached results from recent scans (within last few hours)
3. **Polling**: If a fresh scan is needed, SSLLabs performs comprehensive analysis
4. **Analysis Time**: First scan may take 60-120 seconds; cached results are instant
5. **Results**: Displays security grade, vulnerabilities, certificate info, and recommendations

## Usage

Right-click on TLS/HTTP packets and select:
- `TLS → ASK → Certificate Validity Check` (from TLS SNI field)
- `HTTP → ASK → Certificate Validity Check` (from HTTP Host header)

## Example Output

```
=== SSL/TLS Certificate & Security Analysis ===

--- Data Source ---
Method: SSLLabs API v3 (Qualys SSL Labs)
• Comprehensive SSL/TLS security analysis
• Industry-standard security grading
• Vulnerability detection (Heartbleed, POODLE, etc.)
• Free service, no API key required

Host: example.com
Port: 443

--- Overall Security Grade ---
✓ Grade: A+
(A+ is best, F is worst)

--- Certificate Information ---
Subject: CN=example.com
Issuer: CN=Let's Encrypt Authority X3
Serial Number: 03abc123...
Signature Algorithm: sha256WithRSAEncryption

Valid From: 2026-01-01 00:00:00 UTC
Valid Until: 2026-04-01 00:00:00 UTC

✓ Certificate is valid for 57 more days

--- Supported Protocols ---
TLS 1.3, TLS 1.2

--- Subject Alternative Names (SANs) ---
example.com
www.example.com

--- Certificate Fingerprints ---
SHA256: abc123...
SHA1: def456...

--- Vulnerability Assessment ---
✓ Not vulnerable: Heartbleed
✓ Not vulnerable: POODLE
✓ Not vulnerable: FREAK
✓ Not vulnerable: BEAST
✓ Not vulnerable: Logjam
✓ Not vulnerable: DROWN
✓ No known vulnerabilities detected

--- Security Features ---
✓ Forward Secrecy: Enabled (all ciphers)
✓ RC4 Support: Disabled (good)
HSTS: unknown (max-age: 31536000 seconds)

--- Security Recommendations ---
✓ Certificate validity period is good

--- Additional Resources ---
• Full SSLLabs Report: https://www.ssllabs.com/ssltest/analyze.html?d=example.com
• Mozilla SSL Configuration Generator: https://ssl-config.mozilla.org/
```

## Technical Details

### API Endpoint
- Base URL: `https://api.ssllabs.com/api/v3/analyze`
- Parameters: `?host={domain}&startNew=off&fromCache=on&all=done`
- Rate Limits: Reasonable use (no specific published limit)

### Polling Mechanism
- Initial request checks for cached results
- If analysis needed, polls every 2 seconds
- Maximum 30 polls (60 seconds timeout)
- Status values: READY, IN_PROGRESS, DNS, ERROR

### Data Processing
- Extracts endpoint details from JSON response
- Converts timestamps from milliseconds to readable format
- Calculates days until certificate expiry
- Formats grade with visual indicators
- Processes vulnerability flags
- Displays security feature status

## Migration Notes

### No Code Changes Required
The feature name in Wireshark remains "Certificate Validity Check" in the context menu, but provides much more comprehensive analysis.

### Removed Dependencies
- **OpenSSL**: No longer required for certificate checking
- **ssl-checker.io**: Previous API replaced with SSLLabs

### Maintained Dependencies
- **curl**: Still required for HTTPS API requests (usually pre-installed)

## Smart Fallback for Capacity Issues

When SSLLabs API is at full capacity (peak usage times), ASK automatically:

1. **Detects capacity errors** - Recognizes "running at full capacity" messages
2. **Checks for OpenSSL** - Determines if OpenSSL is installed on your system
3. **Falls back gracefully** - Uses OpenSSL for basic certificate checking if available
4. **Informs the user** - Clear messaging about what happened and next steps

### Fallback Scenarios

**Scenario 1: OpenSSL Available**
- SSLLabs at capacity → Automatically uses OpenSSL fallback
- Returns basic certificate info (subject, issuer, validity dates)
- Result window shows "Method: OpenSSL (fallback - SSLLabs unavailable)"
- Recommends trying again later for full security analysis

**Scenario 2: OpenSSL Not Available**
- SSLLabs at capacity → Returns informative error message
- Explains SSLLabs is busy and suggests trying again later
- Provides OpenSSL installation instructions for future fallback capability

## Known Limitations

1. **Initial Scan Time**: First scan for a domain can take 60-120 seconds
2. **Cache Behavior**: Subsequent scans use cached results (faster but may be slightly outdated)
3. **Rate Limits**: SSLLabs may rate limit excessive requests during peak times
4. **Capacity**: SSLLabs may be at full capacity during peak usage (automatically falls back to OpenSSL if available)
5. **IPv6**: Currently only checks IPv4 endpoints by default

## Future Enhancements

Potential improvements for future versions:
- Option to force fresh scan vs cached results
- IPv6 endpoint analysis
- Certificate chain trust path visualization
- Historical scan comparison
- Custom API endpoint configuration

## Files Updated

All files updated to version 0.2.5:
- `ask.lua` (main plugin)
- `installers/macos/ask.lua`
- `installers/linux/ask.lua`
- `installers/windows/ask.lua`
- `~/.local/lib/wireshark/plugins/ask.lua` (installed plugin)
- `README.md`
- `CHANGELOG.md`

## Version Details

- **Version**: 0.2.5
- **Build String**: "2026-02-03 ssllabs-integration"
- **User-Agent**: "ASK-Wireshark-Plugin/0.2.5"

## Resources

- **SSLLabs**: https://www.ssllabs.com/
- **SSL Server Test**: https://www.ssllabs.com/ssltest/
- **API Documentation**: https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md
- **Mozilla SSL Config**: https://ssl-config.mozilla.org/

---

**Questions or Issues?**  
Please report any issues or questions in the project repository.
