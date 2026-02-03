# Changes in ASK Version 0.2.3

**Release Date:** February 3, 2026  
**Build:** 2026-02-03 shodan-error-fix

## Overview

Version 0.2.3 is a bug fix release that addresses critical issues with Shodan API error handling. The Shodan integration now works much more reliably and provides clearer error messages when issues occur.

## Bug Fixes

### Shodan API Error Handling (Major Fix)

The Shodan API integration had several issues that caused valid responses to be incorrectly treated as errors, and error responses to be poorly handled. This release completely overhauls the error handling logic.

#### Problems Fixed:

1. **Valid JSON responses flagged as errors**
   - Previously, valid Shodan API responses containing fields like `"region_code"`, `"tags"`, or `"ip"` were being incorrectly detected as error responses
   - This was caused by overly aggressive error detection in the `http_get` function and overly broad HTML detection
   - Fixed false positive when JSON data contains words like "cloud" (e.g., in `"tags": ["cloud"]`)
   - Now properly handles valid Shodan data by re-enabling `allow_error_json` option

2. **HTML error pages not detected properly**
   - HTML error pages from Microsoft Azure Web App, Cloudflare, and other proxies were being passed to JSON parser
   - This caused confusing "Failed to parse JSON" errors instead of clear error messages
   - Now detects HTML error pages early (before JSON parsing) by checking for:
     - `<!DOCTYPE`, `<html>`, `<head>`, `<body>` tags (actual HTML)
     - Error page indicators like "Microsoft Azure Web App", "Site Not Configured", "Error 404", "403 Forbidden"
   - Detection is now more precise: only checks for error text if response doesn't start with `{` (not JSON)

3. **Truncated JSON responses**
   - Truncated or incomplete JSON responses were causing cryptic parsing errors
   - Now validates that response starts with `{` or `[` before attempting to parse
   - Provides clear error messages when JSON appears truncated or malformed

4. **Overly complex error recovery**
   - Previous code had multiple layers of error recovery that tried to extract JSON from error messages
   - This complexity caused more bugs than it fixed
   - Simplified to a clean, linear error handling flow

#### Error Messages Improved:

**Before:**
```
Error querying Shodan:
HTTP error: {"region_code": "VA", "tags": ["cloud"], "ip": 585816737...
```

**After:**
```
Successfully retrieved Shodan data for IP: 34.234.218.161
[Shows actual data in result window]
```

**For actual errors:**
```
Shodan API Error: Invalid Response (HTML instead of JSON)

Received an HTML error page instead of JSON response.
Response preview: [first 200 chars]

Common causes:
- API endpoint routing issue (Cloudflare/Azure error)
- Invalid or missing API key
- Rate limiting or access restrictions

Troubleshooting:
1. Verify your API key is correct at: https://account.shodan.io/
2. Check API key file: ~/.ask/SHODAN_API_KEY.txt (ensure no extra spaces/newlines)
3. Verify API key has proper permissions
4. Note: Shodan host lookup requires paid membership ($49+)
5. Try again in a few moments (may be temporary API issue)

Alternative: Use other ASK features (AbuseIPDB, VirusTotal, RDAP, IPinfo)
```

### HTTP Response Processing

Re-enabled the `allow_error_json` option for Shodan API calls. This option tells the HTTP handler to not automatically flag JSON responses containing error-like fields as errors, allowing Shodan's valid responses to be processed correctly.

## Technical Changes

### Code Changes

**File:** `ask.lua`

1. **Simplified Shodan error handling** (lines 3680-3686)
   - Removed complex JSON extraction from error messages
   - Streamlined error path for clarity

2. **Added HTML error detection** (lines 3692-3713)
   - Detects HTML pages before JSON parsing
   - Checks for multiple HTML/error page indicators
   - Provides clear error message with response preview

3. **Added JSON format validation** (lines 3715-3723)
   - Validates response starts with `{` or `[`
   - Catches malformed responses early
   - Better error message for invalid formats

4. **Improved JSON parsing error handling** (lines 3727-3732)
   - Clear message for truncated/malformed JSON
   - Includes response preview in error
   - Suggests alternative ASK features

5. **Better logging throughout**
   - Added log messages for debugging
   - Logs response previews when errors occur
   - Helps diagnose API issues

### Version Updates

- Version updated from 0.2.2 to 0.2.3
- Build string updated to "2026-02-03 shodan-error-fix"
- User-Agent headers updated to "ASK-Wireshark-Plugin/0.2.3"
- Version badge in README updated
- CHANGELOG.md updated with full details

## Upgrade Instructions

### For Existing Users

1. **Simple Method - Using Installer:**
   ```bash
   # macOS/Linux
   cd installers/macos    # or installers/linux
   ./install.sh
   
   # Windows
   cd installers\windows
   .\install.ps1
   ```
   The installer will detect your existing installation and offer to upgrade.

2. **Manual Method:**
   - Replace your existing `ask.lua` with the new version
   - Location depends on platform:
     - **macOS:** `~/.local/lib/wireshark/plugins/ask.lua`
     - **Linux:** `~/.local/lib/wireshark/plugins/ask.lua`
     - **Windows:** `%APPDATA%\Wireshark\plugins\ask.lua`
   - Restart Wireshark

### Verifying the Update

After updating, check the version in Wireshark:
1. Go to **Help → About Wireshark → Plugins**
2. Find "ASK" in the list
3. Verify version shows "0.2.3"

Or check the Shodan result window - it should show:
```
ASK Build: 2026-02-03 shodan-error-fix
```

## Testing

### What to Test

1. **Shodan IP Lookups**
   - Try querying a public IP address with Shodan
   - Should either return data or provide clear error message
   - No more "HTTP error: {..." messages with truncated JSON

2. **Error Scenarios**
   - Test with invalid API key (if you have one)
   - Should get clear error message about authentication
   - Test without API key - should prompt to configure one

3. **Alternative Features**
   - If Shodan doesn't work, try other IP intelligence features:
     - IPinfo (IP Reputation → IPinfo)
     - GreyNoise (no API key required)
     - AbuseIPDB
     - VirusTotal

## Known Issues

None specific to this release. General Shodan notes:

- **Paid Membership Required:** Shodan's host lookup endpoint requires a paid membership ($49 one-time minimum). Free accounts cannot access IP host information.
- **Rate Limits:** Even with paid membership, Shodan has rate limits. If you hit rate limits, you'll see a clear error message.

## Future Improvements

Potential enhancements for future releases:

1. Add support for Shodan's free InternetDB API for basic IP info
2. Cache Shodan responses longer to reduce API usage
3. Add more detailed vulnerability information parsing
4. Improve service banner formatting

## Feedback

If you encounter any issues with this release:

1. Check Wireshark console for `[ASK]` log messages
2. Verify your API key configuration
3. Try alternative ASK features
4. Report issues with console logs to help diagnose problems

## Credits

- **Bug Report:** Issues reported by users experiencing Shodan API errors
- **Fix:** Enhanced error handling and HTML detection
- **Testing:** Verified with various error scenarios and valid responses
