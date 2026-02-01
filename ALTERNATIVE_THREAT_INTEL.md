# Alternative Threat Intelligence Sources for ASK

## Recommended Free/Free-Tier Sources

### 1. **AlienVault OTX (Open Threat Exchange)** ⭐⭐⭐⭐⭐
**Value:** Very High | **Free Tier:** Yes | **API Key Required:** Yes

**What it provides:**
- IP reputation and threat intelligence
- Domain reputation
- URL reputation
- File hash (MD5, SHA1, SHA256) reputation
- Pulse data (threat intelligence reports)
- Historical data
- Community-driven threat intelligence

**Unique Value:**
- Largest free threat intelligence community
- Pulse system - curated threat intelligence reports
- Historical context for IOCs
- Multiple indicator types in one platform
- Community contributions and validation

**API Details:**
- Base URL: `https://otx.alienvault.com/api/v1`
- Endpoints: `/indicators/ip/{ip}`, `/indicators/domain/{domain}`, `/indicators/url/{url}`, `/indicators/file/{hash}`
- Registration: https://otx.alienvault.com (free)
- Rate Limits: Not clearly documented, but generous for free tier

**Use Case:** Comprehensive threat intelligence for IPs, domains, URLs, and file hashes. Perfect for analysts needing context on suspicious indicators.

---

### 2. **GreyNoise** ⭐⭐⭐⭐
**Value:** High | **Free Tier:** Yes (Community API) | **API Key Required:** No (for Community API)

**What it provides:**
- IP classification (noise vs. legitimate)
- Internet scanning detection (last 90 days)
- RIOT dataset (legitimate business services)
- Organization information
- Last seen dates
- Classification (malicious, benign, unknown)

**Unique Value:**
- Identifies internet scanners vs. legitimate services
- Reduces false positives from benign scanning activity
- RIOT dataset helps identify legitimate cloud services
- No authentication needed for Community API

**API Details:**
- Base URL: `https://api.greynoise.io/v3/community`
- Endpoint: `/ip/{ip}`
- Rate Limit: 50 searches per week (combined with Visualizer)
- Registration: Not required for Community API

**Use Case:** Quickly identify if an IP is scanning the internet (noise) or is a legitimate service. Helps reduce alert fatigue.

---

### 3. **Abuse.ch (URLhaus & ThreatFox)** ⭐⭐⭐⭐
**Value:** High | **Free Tier:** Yes | **API Key Required:** Yes (free Auth-Key)

**URLhaus:**
- Malware URL detection
- Payload information
- Malware sample downloads
- Recent malicious URLs (last 3 days)
- Database dumps available

**ThreatFox:**
- IOCs (Indicators of Compromise)
- Malware family identification
- File hash lookups
- IOC search by malware family
- Recent IOCs (last 1-7 days)

**Unique Value:**
- Specialized in malware URLs and IOCs
- Real-time threat data
- Malware family attribution
- Database dumps for offline analysis

**API Details:**
- URLhaus: `https://urlhaus-api.abuse.ch/v1/`
- ThreatFox: `https://threatfox-api.abuse.ch/api/v1/`
- Registration: https://auth.abuse.ch (free Auth-Key)
- Rate Limits: Fair use policy

**Use Case:** Detect malware URLs and IOCs. Perfect for identifying malicious domains/URLs and associated malware families.

---

### 4. **PhishTank** ⭐⭐⭐
**Value:** Medium-High | **Free Tier:** Yes | **API Key Required:** Optional (for higher limits)

**What it provides:**
- Phishing URL detection
- Community-verified phishing sites
- Hourly-updated database
- Database dumps available

**Unique Value:**
- Largest free phishing database
- Community-verified (reduces false positives)
- Database dumps for local lookups
- Operated by Cisco Talos

**API Details:**
- Base URL: `http://checkurl.phishtank.com/checkurl/`
- Method: HTTP POST
- Rate Limits: Restrictive without API key, higher with key
- Registration: Optional (for API key)

**Use Case:** Detect phishing URLs in network traffic. Especially valuable for email analysis and HTTP traffic.

---

### 5. **Google Safe Browsing** ⭐⭐⭐
**Value:** Medium | **Free Tier:** Yes (non-commercial) | **API Key Required:** Yes

**What it provides:**
- Malware URL detection
- Phishing URL detection
- Unwanted software detection
- Social engineering detection

**Unique Value:**
- Google's massive threat database
- Real-time updates
- Multiple threat types
- Privacy-preserving Update API option

**API Details:**
- Lookup API: `https://safebrowsing.googleapis.com/v4/threatMatches:find`
- Update API: For local database downloads
- Registration: Google Cloud Console (free)
- Rate Limits: Default quota, can be increased
- **Restriction:** Non-commercial use only

**Use Case:** URL reputation checking. Good complement to other sources, but limited to non-commercial use.

---

## Comparison Matrix

| Source | IP | Domain | URL | Hash | Phishing | Malware | Free Tier | API Key | Unique Value |
|-------|----|--------|-----|------|----------|---------|-----------|---------|--------------|
| **AlienVault OTX** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Pulse reports, community intel |
| **GreyNoise** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | Scanner detection, RIOT dataset |
| **URLhaus** | ❌ | ❌ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | Malware URLs, payloads |
| **ThreatFox** | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | IOCs, malware families |
| **PhishTank** | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ | ✅ | Optional | Phishing database |
| **Google Safe Browsing** | ❌ | ❌ | ✅ | ❌ | ✅ | ✅ | ✅* | ✅ | Google's threat DB |

*Non-commercial only

---

## Recommended Implementation Priority

### Tier 1: High Value, Easy Integration
1. **GreyNoise** - No API key needed, unique scanner detection
2. **AlienVault OTX** - Comprehensive, free, well-documented

### Tier 2: High Value, Requires API Key
3. **Abuse.ch (URLhaus)** - Specialized malware URL detection
4. **Abuse.ch (ThreatFox)** - IOC and malware family data

### Tier 3: Specialized Use Cases
5. **PhishTank** - Phishing-specific detection
6. **Google Safe Browsing** - If non-commercial use is acceptable

---

## Implementation Recommendations

### For IP Analysis:
- **GreyNoise** - First check (scanner vs legitimate)
- **AlienVault OTX** - Comprehensive threat intel
- **ThreatFox** - IOC and malware family data

### For URL Analysis:
- **URLhaus** - Malware URL detection
- **AlienVault OTX** - General threat intel
- **PhishTank** - Phishing detection
- **Google Safe Browsing** - Additional validation

### For Domain Analysis:
- **AlienVault OTX** - Primary source
- **ThreatFox** - IOC data

### For File Hash Analysis:
- **AlienVault OTX** - Primary source
- **ThreatFox** - Malware family attribution

---

## Additional Considerations

### Data Sources Already in ASK:
- AbuseIPDB - IP abuse reports
- VirusTotal - Multi-engine scanning
- Shodan - IP intelligence (paid)
- IPinfo - IP geolocation/intelligence
- urlscan.io - URL sandbox analysis

### Complementary Value:
- **GreyNoise** complements Shodan/IPinfo by identifying scanners
- **AlienVault OTX** complements VirusTotal with community intel
- **URLhaus** complements urlscan.io with malware-specific data
- **PhishTank** adds phishing-specific detection

---

## Next Steps

1. **Start with GreyNoise** - Easiest (no API key), unique value
2. **Add AlienVault OTX** - Most comprehensive free source
3. **Consider Abuse.ch** - Specialized malware detection
4. **Evaluate PhishTank** - If phishing detection is priority

Each source adds unique value and complements existing ASK capabilities.
