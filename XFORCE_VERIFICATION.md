# IBM X-Force Exchange API Verification

## Summary

Based on research, IBM X-Force Exchange API provides the following endpoints and data:

### Available API Endpoints

1. **IP Reputation** - `/ipr/{ip}`
   - Risk score (1-10 scale)
   - Reason for score
   - Reason description
   - Subnet information
   - ASN data
   - Category descriptions
   - Geographic data

2. **IP History** - `/ipr/history/{ip}`
   - Historical reputation data
   - Timeline information

3. **IP Malware** - `/ipr/malware/{ip}`
   - Associated malware families
   - Malware samples

4. **URL Reputation** - `/url/{url}`
   - Risk score (1-10 scale)
   - Malicious classification
   - Category tags

5. **URL Malware** - `/url/malware/{url}`
   - Associated malware families

6. **CVE Search** - `/vulnerabilities/search/{cve}`
   - CVE information
   - Risk score
   - Exploitability data
   - CVSS scores

### Data Points Available

Based on API documentation and examples:

✅ **Risk Scores** - Available (1-10 scale for IPs, URLs, CVEs)
✅ **Category Tags** - Available (via categoryDescriptions field)
✅ **CVE Data** - Available (via /vulnerabilities/search endpoint)
⚠️ **Threat Actor** - Unclear (may be in malware/history endpoints, needs verification)

### Authentication

- **Method:** Basic Authentication
- **Format:** Base64(API_Key:API_Password)
- **Server:** https://api.xforce.ibmcloud.com
- **Credentials:** Obtained from https://exchange.xforce.ibmcloud.com/settings/api

### Free Tier Verification Needed

**Critical Questions to Verify:**

1. **Free Account Access:**
   - Can free accounts access the API?
   - What are the rate limits for free accounts?
   - Are there any restrictions on endpoints?

2. **Data Availability in Free Tier:**
   - ✅ Risk Scores - Need to verify
   - ✅ Category Tags - Need to verify
   - ✅ CVE Data - Need to verify
   - ⚠️ Threat Actor Information - Need to verify (may require paid tier)

3. **Threat Actor Data:**
   - Is threat actor attribution available in free tier?
   - Which endpoint provides threat actor information?
   - Is it in `/ipr/malware/` or `/ipr/history/` responses?

### Recommended Verification Steps

1. **Register for Free Account:**
   - Visit: https://exchange.xforce.ibmcloud.com
   - Sign up for free account
   - Navigate to Settings → API
   - Generate API Key and API Password

2. **Test API Access:**
   ```bash
   # Test IP reputation endpoint
   curl -u "API_KEY:API_PASSWORD" \
     "https://api.xforce.ibmcloud.com/ipr/8.8.8.8"
   
   # Test CVE endpoint
   curl -u "API_KEY:API_PASSWORD" \
     "https://api.xforce.ibmcloud.com/vulnerabilities/search/CVE-2021-44228"
   
   # Test URL endpoint
   curl -u "API_KEY:API_PASSWORD" \
     "https://api.xforce.ibmcloud.com/url/http://example.com"
   ```

3. **Check Response Structure:**
   - Verify risk score is present
   - Check for category tags/categoryDescriptions
   - Look for threat actor information
   - Verify CVE data structure

4. **Check Rate Limits:**
   - Test multiple requests
   - Look for rate limit headers or errors
   - Document limits if found

### Expected Response Structure (Based on Documentation)

**IP Reputation Response:**
```json
{
  "score": 1-10,
  "reason": "string",
  "reasonDescription": "string",
  "subnets": [
    {
      "subnet": "string",
      "score": 1-10,
      "categoryDescriptions": ["string"],
      "cats": {},
      "asns": []
    }
  ],
  "history": [],
  "malware": []
}
```

**CVE Response:**
```json
{
  "cve": "CVE-XXXX-XXXX",
  "score": 1-10,
  "cvss": {},
  "description": "string"
}
```

### Implementation Plan (After Verification)

If free tier provides access to:
- ✅ Risk Scores
- ✅ Category Tags  
- ✅ CVE Data
- ✅ Threat Actor (if available)

Then implement:
1. **IP Reputation (X-Force)** - Risk score, categories, threat actor
2. **URL Reputation (X-Force)** - Risk score, categories
3. **CVE Lookup (X-Force)** - CVE details, risk score, exploitability
4. **Domain Reputation (X-Force)** - If available

### Next Steps

1. **User Verification:** Register for free account and test API access
2. **Document Findings:** Record what data is available in free tier
3. **Implement Integration:** If verified, add X-Force Exchange to ASK plugin
4. **Update Documentation:** Add X-Force to README, feature matrix, and setup scripts

### References

- API Documentation: https://api.xforce.ibmcloud.com/doc/
- Exchange Portal: https://exchange.xforce.ibmcloud.com/
- API Settings: https://exchange.xforce.ibmcloud.com/settings/api
- Support: xfe@us.ibm.com
