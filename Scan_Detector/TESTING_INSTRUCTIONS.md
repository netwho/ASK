# Testing Instructions for Scan Detector v0.1.0

## The Problem
The plugin was creating duplicate scan entries:
- One with hostname "kali2.netwho.lan" (from Wireshark's name resolution)
- One with IP "172.28.184.67" (from packet header)

## The Fix
Version 0.1.0 now:
- Extracts IPs directly from packet headers (`ip.src`, `ip.dst`)
- Uses only IP addresses for tracking (no more duplicates)
- Builds DNS cache by comparing header IPs with display names
- Shows IP in summary table, hostname in detailed section

## How to Test Properly

### Step 1: Replace the Plugin
```bash
# Copy the new version to your Wireshark plugins directory
cp scan_detector.lua ~/.local/lib/wireshark/plugins/
# OR on some systems:
cp scan_detector.lua ~/.wireshark/plugins/
```

### Step 2: Reload Wireshark
**Option A: Restart Wireshark** (recommended)
```bash
# Close Wireshark completely
# Then reopen it
wireshark your_capture.pcap
```

**Option B: Reload Lua Plugins**
- In Wireshark: `Tools > Reload Lua Plugins` (Ctrl+Shift+L)

### Step 3: Verify Plugin Loaded
Check the Wireshark console output for:
```
========================================
Scan Detector Plugin v0.1.0 Loaded
========================================
```

### Step 4: Clear Old Data
**CRITICAL**: The old scan data is still in memory!
1. Go to `Tools > Scan Detector > Reset Data`
2. You should see a popup saying "Scan detection data has been reset"

### Step 5: Re-analyze the Capture
The plugin only processes packets as they're analyzed. To re-process:

**Option A: Reload the capture file**
```bash
# Close and reopen the file
File > Close
File > Open > your_capture.pcap
```

**Option B: Force re-dissection**
- Select any packet
- Right-click > Protocol Preferences > Force Decode As...
- OR: `Analyze > Reload Packets` (Ctrl+R)

### Step 6: Generate Report
1. Go to `Tools > Scan Detector > Generate Report`
2. Check the output

## Expected Results

### Before Fix:
```
Total Scans Detected: 2

Source IP       Scan Type              Confidence Pkts   Details
-------------------------------------------------------------------------------------
kali2.netwho.la XMAS Scan              HIGH       30     Detected XMAS packets...
172.28.184.67   XMAS Scan              HIGH       4027   Detected XMAS packets...
```

### After Fix:
```
Total Scans Detected: 1

Source IP       Scan Type              Confidence Pkts   Details
-------------------------------------------------------------------------------------
172.28.184.67   XMAS Scan              HIGH       4057   Detected XMAS packets...

DETAILED SCAN ANALYSIS:
-------------------------------------------------------------------------------------

[XMAS Scan] 172.28.184.67
  Hostname:   kali2.netwho.lan
  First Seen: 1703415527.5776
  Last Seen:  1703415535.7187
  Packets:    4057
  Confidence: HIGH
```

## Debug Output

If you see debug messages in the console like:
```
DEBUG: Extracted IP 172.28.184.67 from display name kali2.netwho.lan
DEBUG: Creating scan report with key='172.28.184.67_XMAS Scan', src_ip='172.28.184.67', hostname='kali2.netwho.lan'
```

This confirms:
✅ The plugin is extracting IPs correctly
✅ The DNS cache is working
✅ Only one report entry is created

## Troubleshooting

### Still seeing duplicates?
1. **Did you reset the data?** Old entries persist until cleared
2. **Did you reload the plugin?** Changes require reload
3. **Did you reload the packet file?** Plugin needs to re-process packets

### No hostname in DNS cache?
- This is normal if there's no DNS traffic or name resolution in the capture
- The plugin will show "(not resolved)" which is correct

### Plugin not loading?
Check for Lua syntax errors:
```bash
# Test syntax
lua -l scan_detector.lua
```

## Verification Checklist
- [ ] Plugin shows v0.1.0 on load
- [ ] Used "Reset Data" to clear old scan reports
- [ ] Reloaded the capture file or forced re-dissection
- [ ] Generated new report
- [ ] Only ONE entry per unique IP + scan type combination
- [ ] IP addresses shown in summary table
- [ ] Hostnames shown in detailed section
- [ ] DNS cache populated (if name resolution was captured)
