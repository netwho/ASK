# Duplicate Scan Entry Bug Fix - v0.1.0

## The Problem

When NMAP detection occurred progressively during a scan, the plugin created **duplicate entries** for the same scan:

### Example Bug:
```
Source IP       Scan Type              Confidence Pkts   Details
---------------------------------------------------------------------------------------------
192.168.1.203   ACK Scan               MEDIUM     2      Detected unsolicited ACK packets...
192.168.1.203   Nmap ACK Scan          MEDIUM     63     Detected unsolicited ACK packets...
```

**What Happened:**
1. First 2 ACK packets arrive
2. NMAP score is low (<50%) → Scan type = "ACK Scan"
3. Report key created: `"192.168.1.203_ACK Scan"`
4. More packets arrive, NMAP indicators accumulate
5. NMAP score crosses 50% threshold
6. Scan type changes to "Nmap ACK Scan"
7. **NEW** report key created: `"192.168.1.203_Nmap ACK Scan"`
8. Result: **Two separate entries** tracking the same scan (2 + 63 = 65 total packets split)

## Root Cause

The plugin used the **full scan type name** (including "Nmap" prefix) as part of the report key:

```lua
local report_key = src_ip .. "_" .. scan_type
```

When the scan type name changed from "ACK Scan" to "Nmap ACK Scan", it created a new key and thus a new report entry.

## The Solution

### 1. Introduced Base Scan Types

Created helper functions to separate the base scan type from the NMAP attribution:

```lua
-- Strip "Nmap" prefix to get base type
local function get_base_scan_type(scan_type)
    if scan_type:sub(1, 5) == "Nmap " then
        return scan_type:sub(6)  -- Remove "Nmap " prefix
    end
    return scan_type
end

-- Add "Nmap" prefix if score >= 50%
local function get_display_scan_type(base_type, src_ip)
    if get_nmap_likelihood(src_ip) >= 50 then
        return "Nmap " .. base_type
    end
    return base_type
end
```

### 2. Updated Detection Functions

All TCP scan detection functions now return **base types only**:

**Before:**
```lua
if unique_dests >= config.syn_threshold then
    local scan_type = "SYN Scan"
    if get_nmap_likelihood(src_ip) >= 50 then
        scan_type = "Nmap SYN Scan"  -- ❌ Creates duplicate entries
    end
    return true, scan_type, "HIGH", details
end
```

**After:**
```lua
if unique_dests >= config.syn_threshold then
    return true, "SYN Scan", "HIGH", details  -- ✅ Always returns base type
end
```

### 3. Updated Report Key Logic

The report key now uses the **base scan type** which never changes:

```lua
local base_type = get_base_scan_type(scan_type)
local report_key = src_ip .. "_" .. base_type  -- Uses "ACK Scan" not "Nmap ACK Scan"

scan_data.scan_reports[report_key] = {
    source_ip = src_ip,
    base_scan_type = base_type,  -- Store base type
    -- ... other fields
}
```

### 4. Dynamic Display Name Generation

When displaying reports, the **display name is generated dynamically** based on the **current NMAP score**:

```lua
-- Summary table
local display_type = get_display_scan_type(report.base_scan_type, report.source_ip)
local formatted_scan_type = format_scan_type(display_type, 30)

-- Detailed analysis
report_text = report_text .. string.format("\n[%s] %s\n", display_type, report.source_ip)

-- Statistics
scan_type_counts[display_type] = (scan_type_counts[display_type] or 0) + 1
```

## Result

### After Fix:
```
Source IP       Scan Type              Confidence Pkts   Details
---------------------------------------------------------------------------------------------
192.168.1.203   Nmap ACK Scan          MEDIUM     65     Detected unsolicited ACK packets...
```

**What Now Happens:**
1. First 2 ACK packets arrive
2. NMAP score is low (<50%)
3. Report key created: `"192.168.1.203_ACK Scan"` (base type)
4. Display shows: "ACK Scan" (no NMAP prefix yet)
5. More packets arrive, NMAP indicators accumulate
6. NMAP score crosses 50% threshold
7. **SAME** report key: `"192.168.1.203_ACK Scan"` (base type unchanged)
8. Packet count incremented: 2 → 3 → 4 → ... → 65
9. Display shows: "Nmap ACK Scan" (NMAP prefix added dynamically)
10. Result: **Single entry** with all 65 packets properly counted

## Benefits

### ✅ **No More Duplicates**
- Each unique scan (IP + base type) has exactly one entry
- Packet counts accumulate correctly
- Report remains clean and accurate

### ✅ **NMAP Attribution Still Works**
- NMAP detection continues as packets arrive
- Display name updates automatically when threshold crossed
- No loss of functionality

### ✅ **Backward Compatible**
- Existing detection logic unchanged
- User-Agent detection unaffected
- All scan types handled correctly

### ✅ **Accurate Statistics**
- Total packet counts correct
- No split entries
- Statistics section shows proper counts

## Technical Details

### Base Scan Types
- `SYN Scan`
- `FIN Scan`
- `XMAS Scan`
- `NULL Scan`
- `ACK Scan`
- `UDP Scan`
- `ARP Scan`
- `[Scanner Name]` (for User-Agent detected scanners)

### Report Key Format
```
{source_ip}_{base_scan_type}
```

**Examples:**
- `192.168.1.203_ACK Scan`
- `10.0.0.5_XMAS Scan`
- `172.16.1.100_SYN Scan`

### Display Name Logic
```
IF nmap_likelihood >= 50%:
    display_name = "Nmap " + base_type
ELSE:
    display_name = base_type
```

## Testing

### Before Fix:
```bash
# Run NMAP ACK scan
nmap -sA -p 1-100 target.com

# Old output:
# ACK Scan: 2 packets
# Nmap ACK Scan: 98 packets
# Total: 2 entries (wrong!)
```

### After Fix:
```bash
# Run NMAP ACK scan
nmap -sA -p 1-100 target.com

# New output:
# Nmap ACK Scan: 100 packets
# Total: 1 entry (correct!)
```

## Code Changes Summary

1. **Added helper functions:**
   - `get_base_scan_type()` - Extract base type
   - `get_display_scan_type()` - Generate display name

2. **Updated detection functions:**
   - Removed NMAP prefix logic from return statements
   - All functions return base types only

3. **Updated main dissector:**
   - Extract base type from scan_type
   - Use base type for report key
   - Store `base_scan_type` in report
   - Generate display name dynamically for info column

4. **Updated report generation:**
   - Summary table: Generate display name dynamically
   - Detailed analysis: Generate display name dynamically
   - Statistics: Use display names for counting

## Migration Notes

### For Existing Data

If you have captures already analyzed with the old version:

1. **Reset scan data** before re-analyzing: `Tools > Scan Detector > Reset Data`
2. **Reload the capture** to re-process with new logic
3. Old duplicate entries will be replaced with single consolidated entries

### No Data Loss

- All packets will be counted
- NMAP attribution will be recalculated
- More accurate results than before

## Conclusion

This fix ensures that **each scan is tracked by exactly one report entry**, regardless of when NMAP attribution occurs. Packet counts are accurate, and the display dynamically shows whether the scan is from NMAP based on the latest indicators.

The change is **transparent to users** - reports look the same (or better), but the underlying tracking is now correct and duplicate-free.
