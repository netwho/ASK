# Wireshark Scan Detection Plugin - Installation & Usage Guide

## Overview
This Wireshark Lua plugin detects various network scanning activities including:
- **Nmap scans**: SYN, FIN, XMAS, NULL, ACK, UDP, ARP scans
- **Vulnerability scanners**: Nessus, OpenVAS, Nikto, Acunetix, and others
- **Correlation and reporting**: Aggregates scan data and generates detailed reports

## Installation

### Step 1: Locate Wireshark Plugin Directory

**Windows:**
```
C:\Program Files\Wireshark\plugins\
or
%APPDATA%\Wireshark\plugins\
```

**Linux:**
```
~/.local/lib/wireshark/plugins/
or
/usr/lib/x86_64-linux-gnu/wireshark/plugins/
```

**macOS:**
```
~/.wireshark/plugins/
or
/Applications/Wireshark.app/Contents/PlugIns/wireshark/
```

### Step 2: Install the Plugin

1. Copy `scan_detector.lua` to your Wireshark plugins directory
2. Restart Wireshark
3. Verify installation by checking: **Help > About Wireshark > Plugins** tab
4. Look for "scan_detector.lua" in the list

### Step 3: Verify Plugin is Loaded

Open Wireshark and check the console output. You should see:
```
Scan Detector Plugin Loaded Successfully!
Available menu options:
  - Tools > Scan Detector > Generate Report
  - Tools > Scan Detector > Reset Data
```

## Features

### 1. Automatic Scan Detection

The plugin automatically detects scanning activity in real-time as you capture traffic:

#### TCP-based Scans:
- **SYN Scan**: Most common port scan, sends SYN packets without completing handshake
- **FIN Scan**: Sends packets with only FIN flag to evade firewalls
- **XMAS Scan**: Sends packets with FIN, PSH, and URG flags set
- **NULL Scan**: Sends packets with no TCP flags set
- **ACK Scan**: Used for firewall rule mapping

#### Network Discovery:
- **ARP Scan**: Detects host discovery via ARP requests
- **UDP Scan**: Identifies UDP port scanning activity

#### Vulnerability Scanners:
Detects scanners by User-Agent strings:
- Nessus
- OpenVAS
- Nikto
- Acunetix
- Burp Suite
- OWASP ZAP
- Qualys
- Rapid7 Nexpose/InsightVM

### 2. Display Filters

Use these filters to analyze detected scans:

```wireshark
# Filter by scanning source IP
scandetector.source == "192.168.1.100"

# Filter by scan type
scandetector.type == "SYN Scan"
scandetector.type == "XMAS Scan"
scandetector.type == "Nessus Vulnerability Scanner"

# Filter by confidence level
scandetector.confidence == "HIGH"
scandetector.confidence == "MEDIUM"

# Combine filters
scandetector.source == "10.0.0.5" && scandetector.type == "SYN Scan"
```

### 3. Generate Reports

**Steps:**
1. Capture network traffic or load a PCAP file
2. Go to **Tools > Scan Detector > Generate Report**
3. View detailed scan analysis in popup window

**Report Contents:**
- Total scans detected
- Source IP addresses of scanners
- Scan types identified
- Detection confidence levels
- Packet counts
- First and last seen timestamps
- Detailed scan descriptions
- Statistics by scan type

### 4. Reset Detection Data

To clear all accumulated scan data:
- Go to **Tools > Scan Detector > Reset Data**

## Usage Examples

### Example 1: Detecting Nmap SYN Scan

1. Start packet capture
2. Run nmap from another machine: `nmap -sS 192.168.1.100`
3. Watch the Info column - detected scans will show `[SYN Scan DETECTED]`
4. Generate report to see full details

### Example 2: Identifying Vulnerability Scanner

1. Load a PCAP file containing scanner traffic
2. Apply filter: `scandetector.type contains "Scanner"`
3. View detected vulnerability scanner activity
4. Generate report for complete analysis

### Example 3: Filtering by Scanning Host

1. After detection, find the scanning IP in the report
2. Apply display filter: `scandetector.source == "attacker_ip"`
3. See all scan packets from that specific host

### Example 4: Analyzing Multiple Scan Types

1. Capture traffic during penetration test
2. Generate report to see all scan types used
3. Use the statistics section to understand attack methodology

## Configuration

You can modify detection thresholds in the plugin code:

```lua
local config = {
    syn_threshold = 10,              -- SYN packets before flagging
    port_scan_threshold = 5,         -- Different ports to trigger alert
    time_window = 60,                -- Time window in seconds
    arp_scan_threshold = 5,          -- ARP requests threshold
    udp_scan_threshold = 8           -- UDP packets threshold
}
```

**To adjust:**
1. Open `scan_detector.lua` in a text editor
2. Modify the values in the `config` table
3. Save and reload Wireshark

### Recommended Thresholds:

**For high-traffic networks:**
- Increase thresholds to reduce false positives
- `syn_threshold = 20`, `port_scan_threshold = 10`

**For low-traffic networks:**
- Decrease thresholds for earlier detection
- `syn_threshold = 5`, `port_scan_threshold = 3`

## Detection Logic

### SYN Scan Detection
- Monitors for TCP packets with SYN flag set but no ACK flag
- Tracks unique destination IP:port combinations
- Triggers when threshold exceeded

### FIN/XMAS/NULL Scan Detection
- Analyzes TCP flag combinations
- FIN: Only FIN flag (0x01)
- XMAS: FIN + PSH + URG flags (0x29)
- NULL: No flags set (0x00)

### ACK Scan Detection
- Identifies unsolicited ACK packets
- Distinguishes from legitimate connection ACKs
- Tracks packets to non-established connections

### ARP Scan Detection
- Monitors ARP request patterns
- Counts requests to different target IPs
- Common in network discovery phase

### UDP Scan Detection
- Tracks UDP packets to multiple ports
- Distinguishes from normal application traffic
- Detects port sweeping behavior

### Vulnerability Scanner Detection
- Parses HTTP User-Agent headers
- Matches against known scanner signatures
- Provides high confidence detection

## Troubleshooting

### Plugin Not Loading
1. Check file location is correct
2. Verify Lua syntax: `lua scan_detector.lua` (should have no errors)
3. Check Wireshark version supports Lua plugins
4. Look at **Help > About Wireshark > Folders** for plugin paths

### No Scans Detected
1. Ensure you're capturing traffic with actual scanning activity
2. Lower detection thresholds if network is low-traffic
3. Check that required fields are available (tcp.flags, etc.)
4. Verify display filters are not hiding detections

### High False Positives
1. Increase detection thresholds in config
2. Adjust time_window to better match your network
3. Consider your network's normal traffic patterns

## Advanced Features

### Adding Custom Scanner Signatures

Edit the `scanner_signatures` table:

```lua
local scanner_signatures = {
    user_agents = {
        ["YourScanner"] = "Custom Scanner Name",
        ["CustomTool"] = "My Custom Tool"
    }
}
```

### Export Report Data

The report window can be:
1. Copied to clipboard (Ctrl+A, Ctrl+C)
2. Saved to file
3. Imported into analysis tools

## Performance Considerations

- Plugin processes every packet in real-time
- For large PCAPs (>1GB), consider:
  - Processing in chunks
  - Using display filters before analysis
  - Increasing time_window to reduce granularity

## Security Notes

This plugin is designed for:
- Network security monitoring
- Penetration testing analysis
- Incident response
- Security research

**Legal Notice**: Only use on networks you own or have explicit permission to monitor.

## Support & Development

### Adding New Scan Types

To add detection for new scan patterns:

1. Create detection function following existing pattern:
```lua
local function detect_new_scan(pinfo, src_ip, ...)
    -- Detection logic
    if condition_met then
        return true, "Scan Name", "Confidence", "Details"
    end
    return false, nil, nil, nil
end
```

2. Call in main dissector function
3. Test with sample traffic

### Enhancing Scanner Database

Add more User-Agent signatures to improve vulnerability scanner detection.

## Version History

**v1.0** - Initial release
- TCP scan detection (SYN, FIN, XMAS, NULL, ACK)
- UDP and ARP scan detection
- Vulnerability scanner detection
- Report generation
- Display filter support

## License

This plugin is provided as-is for network security analysis purposes.

## Contact

For bugs, enhancements, or questions about this plugin, please document your findings and share with the security community.
