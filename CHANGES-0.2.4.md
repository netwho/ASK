# Changes in ASK Version 0.2.4

**Release Date:** February 3, 2026  
**Build:** 2026-02-03 logging-clipboard

## Overview

Version 0.2.4 introduces significant new features for logging and clipboard management, allowing analysts to save and share their investigation results efficiently. This release also includes the Shodan API error handling fixes from 0.2.3.

## New Features

### 1. ASK Documents Directory

**Automatic Directory Creation:**
- Creates `~/Documents/ASK/` on plugin load
- Platform-specific paths:
  - **macOS/Linux:** `~/Documents/ASK/`
  - **Windows:** `%USERPROFILE%\Documents\ASK\`
- Verified with write test on initialization
- Console confirmation: `[ASK] ASK directory initialized: ~/Documents/ASK`

**Purpose:**
- Centralized location for all ASK log files
- Easy to find and access investigation results
- Separate from Wireshark configuration

### 2. Daily Log Files

**Automatic Log File Management:**
- **Format:** `ASK-YYYY-MM-DD.log`
- **Example:** `ASK-2026-02-03.log`
- One file per day for all queries
- Append-only format (never overwrites)

**Log Entry Format:**
```
================================================================================
Timestamp: 2026-02-03 11:15:30
Query Type: Shodan
Query Target: 34.236.0.203
--------------------------------------------------------------------------------
=== IP Intelligence (Shodan) ===

[Full query results here...]

```

**Each Entry Includes:**
- Timestamp (YYYY-MM-DD HH:MM:SS)
- Query Type (DNS RDAP, Shodan, VirusTotal IP, etc.)
- Query Target (IP address, domain, URL)
- Complete query results (formatted exactly as shown in result window)
- Separator lines for easy reading

### 3. Copy to Clipboard Button

**Platform-Specific Implementation:**
- **macOS:** Uses `pbcopy` (pre-installed)
- **Linux:** Uses `xclip` or `xsel` (auto-detected)
- **Windows:** Uses `clip` command (Windows 10+)

**Features:**
- One-click copy of entire result
- Console confirmation when successful
- Error message if clipboard tool not available
- Preserves formatting

**Usage:**
1. Run any query (Shodan, DNS RDAP, etc.)
2. Result window appears
3. Click "Copy to Clipboard" button
4. Content is now in your clipboard
5. Paste anywhere (email, document, chat, etc.)

### 4. Save to Log Button

**Functionality:**
- Appends result to today's log file
- Creates log file if it doesn't exist
- Shows confirmation window with:
  - Log file path
  - Query type
  - Query target

**Benefits:**
- Build investigation timeline
- Share findings with team
- Create audit trail
- Reference past queries

**Usage:**
1. Run any query
2. Result window appears
3. Click "Save to Log" button
4. Confirmation shows file location
5. Result appended to `ASK-YYYY-MM-DD.log`

### 5. Enhanced Result Windows

**Updated Query Types (9 total):**
1. **DNS RDAP** - Domain registration lookups
2. **IP RDAP** - IP registration information
3. **AbuseIPDB** - IP reputation
4. **VirusTotal IP** - IP reputation
5. **VirusTotal Domain** - Domain reputation
6. **VirusTotal URL** - URL scanning
7. **Shodan** - IP intelligence
8. **IPinfo** - IP geolocation/intelligence
9. **urlscan.io** - URL reputation

**Window Layout:**
```
[Copy to Clipboard] [Save to Log]

=== Query Results ===
[Results displayed here...]
```

## Bug Fixes (from 0.2.3)

### Shodan API Error Handling

**Issue Fixed:**
- HTML content embedded in JSON responses was triggering false error detection
- Shodan scans include HTML from target servers: `"html": "<!DOCTYPE html>..."`
- Old code checked entire response for HTML tags
- This caused valid Shodan data to be flagged as error pages

**Solution:**
- HTML detection now only checks **start** of response
- Uses `^` anchor in pattern matching: `^<!DOCTYPE`, `^<html>`
- Embedded HTML in JSON data no longer triggers false positives

**Before:**
```
Error querying Shodan:
HTTP error: {"region_code": "VA", "tags": ["cloud"]...
```

**After:**
```
=== IP Intelligence (Shodan) ===
IP Address: 34.236.0.203
Organization: Amazon Technologies Inc.
...
```

## Technical Implementation

### New Functions

**Directory Management:**
```lua
init_ask_directory()          -- Creates Documents/ASK directory
get_date_string()             -- Returns YYYY-MM-DD
get_timestamp()               -- Returns YYYY-MM-DD HH:MM:SS
```

**Logging:**
```lua
append_to_log(query_type, target, content)  -- Appends to daily log
```

**Clipboard:**
```lua
copy_to_clipboard(text)       -- Platform-specific copy
```

**UI:**
```lua
show_result_window_with_buttons(title, content, type, target)
```

### Initialization Sequence

1. Plugin loads
2. `ASK_DOCS_DIR = init_ask_directory()` executes
3. Directory created (if doesn't exist)
4. Write test performed
5. Console logs confirmation or warning
6. Plugin continues loading normally

### Platform Compatibility

| Feature | macOS | Linux | Windows |
|---------|-------|-------|---------|
| Directory Creation | ✅ | ✅ | ✅ |
| Log Files | ✅ | ✅ | ✅ |
| Clipboard (pbcopy) | ✅ | ❌ | ❌ |
| Clipboard (xclip/xsel) | ❌ | ✅ | ❌ |
| Clipboard (clip) | ❌ | ❌ | ✅ |

## Upgrade Instructions

### From 0.2.3 or Earlier

**Method 1: Using Installer**
```bash
# macOS/Linux
cd installers/macos  # or installers/linux
./install.sh

# Windows
cd installers\windows
.\install.ps1
```

**Method 2: Manual**
```bash
# macOS/Linux
cp ask.lua ~/.local/lib/wireshark/plugins/ask.lua

# Windows
copy ask.lua %APPDATA%\Wireshark\plugins\ask.lua
```

**Restart Wireshark** to load the new version.

### Verify Installation

1. **Check Version:**
   - Help → About Wireshark → Plugins
   - Find "ASK" → version should show "0.2.4"

2. **Check Console:**
   ```
   [ASK] Analyst's Shark Knife (ASK) plugin v0.2.4 loaded successfully
   [ASK] ASK directory initialized: ~/Documents/ASK
   ```

3. **Test Features:**
   - Run any query
   - Verify buttons appear: "Copy to Clipboard" and "Save to Log"
   - Click buttons to test functionality

## Usage Examples

### Example 1: Investigate Suspicious IP

```
1. Right-click IP → ASK → IP Intelligence (Shodan)
2. Review results
3. Click "Save to Log" to document findings
4. Click "Copy to Clipboard" to share with team
5. Paste into incident report
```

### Example 2: Daily Investigation Log

```
Morning:
- Query 5 IPs from firewall alerts
- Save each to log

End of day:
- Review ~/Documents/ASK/ASK-2026-02-03.log
- All queries documented with timestamps
- Complete investigation timeline
```

### Example 3: Team Collaboration

```
1. Analyze domain with DNS RDAP
2. Copy results to clipboard
3. Paste into team chat or email
4. Team members have exact same data
5. Log saved for audit trail
```

## Log File Management

### Viewing Logs

**macOS/Linux:**
```bash
# Today's log
cat ~/Documents/ASK/ASK-$(date +%Y-%m-%d).log

# Specific date
cat ~/Documents/ASK/ASK-2026-02-03.log

# List all logs
ls -lh ~/Documents/ASK/

# Open directory
open ~/Documents/ASK/
```

**Windows:**
```powershell
# Today's log
type $env:USERPROFILE\Documents\ASK\ASK-$(Get-Date -Format "yyyy-MM-dd").log

# Open directory
explorer $env:USERPROFILE\Documents\ASK\
```

### Searching Logs

```bash
# Search all logs for IP address
grep -r "34.236.0.203" ~/Documents/ASK/

# Search for specific query type
grep "Query Type: Shodan" ~/Documents/ASK/*.log

# Count queries by date
wc -l ~/Documents/ASK/ASK-2026-02-*.log
```

## Troubleshooting

### Directory Not Created

**Symptom:** Warning in console
```
[ASK] WARNING: Cannot write to ASK directory - logging disabled
```

**Solutions:**
1. Verify Documents folder exists
2. Check permissions: `ls -ld ~/Documents`
3. Try creating manually: `mkdir -p ~/Documents/ASK`
4. Check Wireshark has write permissions

### Clipboard Not Working

**macOS:**
```bash
which pbcopy  # Should return /usr/bin/pbcopy
```

**Linux:**
```bash
# Install xclip
sudo apt-get install xclip  # Ubuntu/Debian
sudo yum install xclip      # Fedora/RHEL
sudo pacman -S xclip        # Arch
```

**Windows:**
- `clip` command built-in on Windows 10+
- If not working, check Windows version

### Log Button Shows Error

**Check:**
1. ASK directory exists: `ls ~/Documents/ASK`
2. Directory writable: `touch ~/Documents/ASK/test && rm ~/Documents/ASK/test`
3. Console shows initialization message

## Known Issues

**None specific to 0.2.4**

General notes:
- Remaining query types not yet updated (will be in future versions)
- No log rotation yet (may want to manually clean old logs)
- No log export formats yet (CSV, JSON planned)

## Future Enhancements

Planned for future releases:
- Update remaining query types with buttons
- Log rotation/cleanup
- Export logs to JSON/CSV
- Search/filter within logs
- Log compression
- Configurable log directory
- Log analysis tools

## Version Information

- **Version:** 0.2.4
- **Build:** 2026-02-03 logging-clipboard
- **Release Date:** February 3, 2026
- **Previous Version:** 0.2.3 (Shodan fix)

## Credits

- **Feature Request:** User request for logging and clipboard functionality
- **Implementation:** Full logging and clipboard system with platform support
- **Testing:** Verified on macOS with Shodan, DNS RDAP, and other queries

## Documentation

- **README.md** - Updated with version 0.2.4 info
- **CHANGELOG.md** - Full changelog entry
- **FEATURES-LOGGING-CLIPBOARD.md** - Detailed feature documentation
- **This Document** - Complete changes and usage guide
