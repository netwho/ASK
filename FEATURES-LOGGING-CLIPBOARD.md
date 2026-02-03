# ASK Logging and Clipboard Features

## Overview

Version 0.2.4 includes new logging and clipboard features that allow you to save query results to daily log files and copy results to your clipboard.

## Features Added

### 1. ASK Documents Directory

On plugin load, ASK automatically creates a directory at:
- **macOS/Linux:** `~/Documents/ASK/`
- **Windows:** `%USERPROFILE%\Documents\ASK\`

This directory stores daily log files with all your query results.

### 2. Daily Log Files

Log files are automatically created with the naming pattern:
- **Format:** `ASK-YYYY-MM-DD.log`
- **Example:** `ASK-2026-02-03.log`

Each log entry includes:
- Timestamp (YYYY-MM-DD HH:MM:SS)
- Query Type (e.g., "DNS RDAP", "Shodan", "VirusTotal IP")
- Query Target (IP address, domain, URL, etc.)
- Full query results

### 3. Result Window Buttons

Query result windows now include two buttons:

#### **Copy to Clipboard**
- Copies the entire result to your system clipboard
- Works on macOS (pbcopy), Linux (xclip/xsel), and Windows (clip)
- Provides console confirmation when successful

#### **Save to Log**
- Appends the result to today's log file in `~/Documents/ASK/`
- Shows a confirmation window with the log file path
- Log entries are separated with dividers for easy reading

## Supported Queries

The following query types now have Copy/Log functionality:

1. **DNS RDAP** - Domain registration lookups
2. **IP RDAP** - IP registration information  
3. **AbuseIPDB** - IP reputation
4. **VirusTotal IP** - IP reputation
5. **VirusTotal Domain** - Domain reputation
6. **VirusTotal URL** - URL scanning
7. **Shodan** - IP intelligence
8. **IPinfo** - IP geolocation and intelligence
9. **urlscan.io** - URL reputation

*Note: More query types will be updated in future versions*

## Usage

### Using the Buttons

1. Right-click on a packet field → ASK → [Choose Query Type]
2. Result window appears with query results
3. Click **"Copy to Clipboard"** to copy results
4. Click **"Save to Log"** to append to daily log file

### Viewing Log Files

**macOS/Linux:**
```bash
# View today's log
cat ~/Documents/ASK/ASK-$(date +%Y-%m-%d).log

# View all logs
ls ~/Documents/ASK/

# Open directory
open ~/Documents/ASK/
```

**Windows:**
```powershell
# View today's log
type $env:USERPROFILE\Documents\ASK\ASK-$(Get-Date -Format "yyyy-MM-dd").log

# Open directory
explorer $env:USERPROFILE\Documents\ASK\
```

## Log File Format

Each log entry follows this format:

```
================================================================================
Timestamp: 2026-02-03 10:30:45
Query Type: Shodan
Query Target: 34.236.0.203
--------------------------------------------------------------------------------
=== IP Intelligence (Shodan) ===

ASK Build: 2026-02-03 shodan-error-fix

IP Address: 34.236.0.203
Organization: Amazon Technologies Inc.
ISP: Amazon.com, Inc.
...

```

## Platform Support

### Clipboard Functionality

| Platform | Tool Used | Auto-Detected |
|----------|-----------|---------------|
| macOS | `pbcopy` | ✅ Yes |
| Linux | `xclip` or `xsel` | ✅ Yes |
| Windows | `clip` | ✅ Yes |

### Directory Creation

All platforms automatically create the `~/Documents/ASK/` directory on first load.

## Technical Details

### Functions Added

- `init_ask_directory()` - Creates ASK directory in Documents folder
- `get_date_string()` - Returns current date in YYYY-MM-DD format
- `get_timestamp()` - Returns current timestamp for log entries
- `append_to_log(query_type, target, content)` - Appends to daily log
- `copy_to_clipboard(text)` - Copies text to system clipboard
- `show_result_window_with_buttons(title, content, type, target)` - Enhanced result window

### Initialization

The ASK directory is initialized when the plugin loads:
```lua
ASK_DOCS_DIR = init_ask_directory()
```

Console output confirms initialization:
```
[ASK] ASK directory initialized: /Users/walterh/Documents/ASK
```

## Troubleshooting

### Clipboard Not Working

**macOS:** pbcopy should be pre-installed
```bash
which pbcopy
```

**Linux:** Install xclip or xsel
```bash
# Ubuntu/Debian
sudo apt-get install xclip

# Fedora/RHEL
sudo yum install xclip

# Arch
sudo pacman -S xclip
```

**Windows:** clip command is built-in on Windows 10+

### Log Files Not Created

1. Check console for errors: `[ASK] WARNING: Cannot write to ASK directory`
2. Verify Documents folder exists
3. Check file permissions

### Directory Permissions

The plugin tests write access by creating a `.ask_test` file and then removing it. If this fails, logging will be disabled but the plugin will continue to work.

## Future Enhancements

Planned improvements:
- Export logs in JSON/CSV format
- Log rotation (automatic cleanup of old logs)
- Configurable log directory
- Search within logs
- Log compression for old files
- Update remaining query types to use new button system

## Changelog Entry

```
## [0.2.4] - 2026-02-03

### Added
- **ASK Documents Directory** - Auto-creates ~/Documents/ASK/ for log storage
- **Daily Log Files** - Query results saved to daily logs (ASK-YYYY-MM-DD.log)
- **Copy to Clipboard** - Button in result windows to copy results
- **Save to Log** - Button in result windows to append to daily log
- Platform-specific clipboard support (pbcopy/xclip/clip)
- Log entries include timestamp, query type, and target
```

## Version

These features are included in:
- **Version:** 0.2.4
- **Build:** 2026-02-03 logging-clipboard
