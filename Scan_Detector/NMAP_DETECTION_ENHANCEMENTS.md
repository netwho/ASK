# NMAP Detection Enhancements - v0.1.1

## Overview
The Scan Detector plugin has been enhanced to specifically identify NMAP scans and NMAP NSE (Nmap Scripting Engine) vulnerability scans.

## What's New

### 1. NMAP NSE Vulnerability Scanner Detection
Added detection for NMAP's vulnerability scanning capabilities through User-Agent signatures:

**Detected User-Agents:**
- `Nmap Scripting Engine`
- `nmap.org/book/nse.html`

When NMAP NSE scripts make HTTP/HTTPS requests (common in vulnerability scans), they'll be detected and reported as:
```
Nmap NSE Vulnerability Scanner
```

**Example NMAP vuln scan:**
```bash
nmap --script vuln target.com
nmap --script http-vuln-* target.com
nmap --script ssl-* target.com
```

### 2. TCP Scan Type Identification
The plugin now distinguishes between generic scans and NMAP-specific scans by analyzing:

#### Detection Indicators:
1. **TCP Window Sizes**: NMAP commonly uses specific window sizes
   - 63, 1024, 2048, 3072, 4096, 5840, 8192, 16384

2. **Scan Timing**: Rapid sequential scanning patterns
   - High packet rate (>50 packets)
   - Timing consistency

3. **Window Size Variety**: NMAP often varies window sizes
   - 3+ different window sizes indicates NMAP

#### Scoring System:
- **TCP Window Match**: +30 points
- **High Packet Count (>50)**: +40 points
- **Window Variety (3+)**: +30 points
- **Threshold**: 50+ points = "Likely NMAP"

### 3. Enhanced Scan Type Reporting

The plugin now reports scan types with NMAP identification:

**Before:**
```
XMAS Scan
SYN Scan
FIN Scan
NULL Scan
ACK Scan
```

**After (when NMAP detected):**
```
Nmap XMAS Scan
Nmap SYN Scan
Nmap FIN Scan
Nmap NULL Scan
Nmap ACK Scan
```

### 4. NMAP Likelihood Score in Reports

The detailed analysis now shows NMAP likelihood:

```
[Nmap XMAS Scan] 172.28.184.67
  Hostname:   kali2.netwho.lan
  First Seen: 1703415527.5776
  Last Seen:  1703415535.7187
  Packets:    4057
  Confidence: HIGH
  Nmap Score: 80% (Very likely Nmap)
  Details:    Detected XMAS packets to 5 different ports
```

**Score Interpretation:**
- **70-100%**: Very likely Nmap
- **50-69%**: Likely Nmap
- **1-49%**: Possibly Nmap
- **0%**: Not shown (generic scan)

## How It Works

### TCP-Based Scan Detection
For each TCP packet from a scanning source:

1. **Extract Window Size**: Read TCP window size from packet header
2. **Track Timing**: Record packet timestamps
3. **Analyze Pattern**: Compare against NMAP patterns
4. **Calculate Score**: Sum indicator matches
5. **Label Scan**: If score ≥50%, prefix scan type with "Nmap"

### User-Agent Detection
For HTTP/HTTPS traffic:

1. **Extract User-Agent**: Read HTTP User-Agent header
2. **Pattern Match**: Check against NMAP NSE signatures
3. **Report**: Immediately identify as "Nmap NSE Vulnerability Scanner"

## Example Detection Scenarios

### Scenario 1: NMAP Port Scan
```bash
nmap -sX target.com  # XMAS scan
```

**Detection:**
- Window sizes: 1024, 2048, 4096 (+30 points for match)
- Packet count: 1000 ports (+40 points for high rate)
- Window variety: 3 different sizes (+30 points)
- **Total: 100 points** → "Nmap XMAS Scan"

### Scenario 2: NMAP Vulnerability Scan
```bash
nmap --script vuln target.com
```

**Detection:**
- HTTP User-Agent contains "Nmap Scripting Engine"
- **Immediate detection** → "Nmap NSE Vulnerability Scanner"
- Confidence: HIGH

### Scenario 3: Manual/Custom XMAS Scan
```python
# Custom Python scanner with random window sizes
# Not matching NMAP patterns
```

**Detection:**
- Window sizes: random values (0 points)
- Packet count: low/variable (0-20 points)
- Window variety: varies (0-30 points)
- **Total: <50 points** → "XMAS Scan" (generic, no NMAP label)

## Technical Details

### New Data Structures
```lua
nmap_indicators[ip] = {
    window_sizes = {},      -- Track observed TCP window sizes
    packet_times = {},      -- Track packet timestamps
    nmap_likelihood = 0     -- Calculated score (0-100)
}
```

### New Field Extractors
- `tcp.window_size_value`: Extract TCP window size for pattern analysis

### Updated Functions
All TCP scan detection functions now:
- Accept `tcp_window` and `timestamp` parameters
- Track NMAP indicators
- Return "Nmap [Scan Type]" when likelihood ≥ 50%

## Limitations

1. **False Positives**: Other scanners mimicking NMAP patterns may be misidentified
2. **Encrypted Traffic**: HTTPS vulnerability scans won't show User-Agent unless decrypted
3. **Custom NMAP Builds**: Modified NMAP versions with different patterns may not be detected
4. **NSE Script Detection**: Only HTTP-based NSE scripts are detected via User-Agent

## Testing NMAP Detection

### Test 1: NMAP Port Scan
```bash
# Run NMAP scan
nmap -sX -p 1-1000 target.com

# Check report - should show "Nmap XMAS Scan" with high likelihood score
```

### Test 2: NMAP Vuln Scan
```bash
# Run NMAP vulnerability scan
nmap --script http-vuln-cve2017-5638 target.com

# Check report - should detect "Nmap NSE Vulnerability Scanner"
```

### Test 3: Comparison
```bash
# Run generic scan tool (masscan, etc.)
masscan -p80,443 target.com

# Check report - should show generic scan type without "Nmap" prefix
```

## Configuration

### Adjusting NMAP Detection Sensitivity

Edit `config` in the Lua script:

```lua
local nmap_patterns = {
    common_windows = {63, 1024, 2048, 3072, 4096, 5840, 8192, 16384},
    timing_threshold = 100  -- Packets per second
}
```

**To increase sensitivity** (more false positives):
- Lower the 50-point threshold in detection functions
- Add more window sizes to `common_windows`

**To decrease sensitivity** (fewer false positives):
- Raise the 50-point threshold
- Remove less common window sizes

## Summary

The enhanced plugin now:
✅ Detects NMAP NSE vulnerability scans via User-Agent
✅ Identifies NMAP TCP scans via pattern analysis
✅ Reports NMAP likelihood scores
✅ Distinguishes NMAP from generic scanners
✅ Provides detailed NMAP attribution in reports

This helps security analysts:
- Quickly identify NMAP-specific scan activity
- Differentiate professional scanning tools from amateur attempts
- Prioritize investigation of sophisticated scanning activity
- Correlate scan types with known attacker TTPs (NMAP is common in reconnaissance)
