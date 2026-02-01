# Wireshark Scan Detector - Testing & Validation Guide

## Testing Overview

This guide provides practical examples and test scenarios to validate the scan detection plugin's functionality.

## Test Environment Setup

### Prerequisites
- Wireshark with scan_detector.lua plugin installed
- Two machines (or VMs) on the same network:
  - **Scanner**: Machine to run scanning tools (e.g., 192.168.1.50)
  - **Target**: Machine to scan (e.g., 192.168.1.100)
- Packet capture privileges

### Recommended Tools
- **Nmap**: For various scan types
- **Nessus/OpenVAS**: For vulnerability scanning (optional)
- **hping3**: For crafting custom packets
- **netdiscover**: For ARP scanning

## Test Scenarios

### Test 1: SYN Scan Detection

**Objective**: Verify detection of TCP SYN port scans

**Commands to Generate Traffic**:
```bash
# From scanner machine
nmap -sS 192.168.1.100 -p 1-1000

# Alternative with hping3
hping3 -S 192.168.1.100 -p 80 -c 5
```

**Expected Results**:
- Plugin detects SYN scan pattern
- Info column shows: `[SYN Scan DETECTED]`
- Display filter `scandetector.type == "SYN Scan"` shows detections
- Report shows:
  - Scan Type: SYN Scan
  - Confidence: HIGH
  - Source IP: 192.168.1.50
  - Details: "Detected X SYN packets to different targets"

**Validation Steps**:
1. Start Wireshark capture on target or monitoring machine
2. Run nmap SYN scan command
3. Watch for detection in Info column
4. Apply filter: `scandetector.source == "192.168.1.50"`
5. Generate report and verify SYN Scan entry
6. Packet count should be > 10 (syn_threshold)

---

### Test 2: FIN Scan Detection

**Objective**: Verify detection of stealth FIN scans

**Commands to Generate Traffic**:
```bash
# FIN scan with nmap
nmap -sF 192.168.1.100 -p 20-100

# FIN scan with hping3
hping3 -F 192.168.1.100 -p 80 -c 10
```

**Expected Results**:
- Detection of FIN scan pattern
- Confidence: HIGH
- Details show count of FIN packets to different ports

**Validation Steps**:
1. Capture traffic during FIN scan
2. Verify TCP flags = 0x01 (FIN only) in packet details
3. Apply filter: `scandetector.type == "FIN Scan"`
4. Check report for accurate port count

---

### Test 3: XMAS Scan Detection

**Objective**: Verify detection of XMAS tree scans

**Commands to Generate Traffic**:
```bash
# XMAS scan with nmap
nmap -sX 192.168.1.100 -p 1-500

# XMAS scan with hping3
hping3 -F -P -U 192.168.1.100 -p 443 -c 15
```

**Expected Results**:
- Detection of XMAS scan (FIN+PSH+URG flags)
- TCP flags = 0x29 in packet details
- Scan Type: XMAS Scan

**Validation Steps**:
1. Verify TCP flags show FIN, PSH, URG all set
2. Apply filter: `tcp.flags == 0x29`
3. Cross-reference with `scandetector.type == "XMAS Scan"`

---

### Test 4: NULL Scan Detection

**Objective**: Verify detection of NULL scans

**Commands to Generate Traffic**:
```bash
# NULL scan with nmap
nmap -sN 192.168.1.100 -p 1-100

# NULL scan with hping3
hping3 -c 10 -V 192.168.1.100 -p 22
```

**Expected Results**:
- TCP packets with no flags set (0x00)
- Scan Type: NULL Scan
- Confidence: HIGH

---

### Test 5: ACK Scan Detection

**Objective**: Verify detection of firewall ACK scans

**Commands to Generate Traffic**:
```bash
# ACK scan with nmap
nmap -sA 192.168.1.100 -p 1-1000

# ACK scan with hping3
hping3 -A 192.168.1.100 -p 80 -c 20
```

**Expected Results**:
- Unsolicited ACK packets detected
- Scan Type: ACK Scan
- Confidence: MEDIUM (ACK scans can be part of normal traffic)

**Validation Notes**:
- Plugin distinguishes between legitimate ACKs (established connections) and scan ACKs
- Only flagged if no corresponding SYN/SYN-ACK seen

---

### Test 6: UDP Scan Detection

**Objective**: Verify detection of UDP port scans

**Commands to Generate Traffic**:
```bash
# UDP scan with nmap
nmap -sU 192.168.1.100 -p 53,67,68,69,161,162,500

# UDP scan with hping3
hping3 --udp 192.168.1.100 -p 161 -c 20
```

**Expected Results**:
- UDP packets to multiple ports tracked
- Scan Type: UDP Scan
- Confidence: MEDIUM
- Threshold: 8+ different ports

**Validation Steps**:
1. Filter: `udp && ip.src == 192.168.1.50`
2. Count unique destination ports manually
3. Compare with plugin detection

---

### Test 7: ARP Scan Detection

**Objective**: Verify detection of network discovery via ARP

**Commands to Generate Traffic**:
```bash
# ARP scan with nmap
nmap -PR 192.168.1.0/24

# ARP scan with netdiscover
netdiscover -r 192.168.1.0/24 -i eth0

# ARP scan with arp-scan
arp-scan --interface=eth0 192.168.1.0/24
```

**Expected Results**:
- Multiple ARP requests to sequential IPs
- Scan Type: ARP Scan
- Confidence: HIGH
- Details: "Detected ARP requests to X different IPs"

**Validation Steps**:
1. Filter: `arp.opcode == 1` (ARP requests)
2. Check source MAC/IP consistency
3. Verify target IP diversity
4. Plugin should trigger at 5+ unique targets

---

### Test 8: Vulnerability Scanner Detection (Nessus)

**Objective**: Verify detection via HTTP User-Agent

**Simulated Traffic** (if no real scanner available):
```bash
# Simulate Nessus scan with curl
curl -A "Mozilla/5.0 (compatible; Nessus/10.0)" http://192.168.1.100
curl -A "Mozilla/5.0 (compatible; Nessus/10.0)" http://192.168.1.100/admin
curl -A "Mozilla/5.0 (compatible; Nessus/10.0)" http://192.168.1.100/login
```

**Expected Results**:
- Scan Type: Nessus Vulnerability Scanner
- Confidence: HIGH
- Details: "Detected via User-Agent: Mozilla/5.0 (compatible; Nessus/10.0)"

**Validation Steps**:
1. Filter: `http.user_agent contains "Nessus"`
2. Verify plugin correlates HTTP requests
3. Check report shows scanner identification

---

### Test 9: OpenVAS Detection

**Simulated Traffic**:
```bash
# Simulate OpenVAS scan
curl -A "Mozilla/5.0 [en] (X11, U; OpenVAS 9.0.3)" http://192.168.1.100
```

**Expected Results**:
- Scan Type: OpenVAS Security Scanner
- Detection via User-Agent matching

---

### Test 10: Nikto Web Scanner Detection

**Commands** (requires Nikto installed):
```bash
# Run Nikto web scan
nikto -h 192.168.1.100
```

**Expected Results**:
- Scan Type: Nikto Web Scanner
- User-Agent contains "Nikto"
- Multiple HTTP requests to various paths

---

### Test 11: Multiple Concurrent Scans

**Objective**: Test plugin's ability to track multiple scanners simultaneously

**Commands**:
```bash
# From Scanner 1 (192.168.1.50)
nmap -sS 192.168.1.100 &

# From Scanner 2 (192.168.1.51)  
nmap -sU 192.168.1.100 &

# From Scanner 3 (192.168.1.52)
nmap -PR 192.168.1.0/24 &
```

**Expected Results**:
- Report shows 3 separate scan entries
- Each scanner IP tracked independently
- Different scan types identified correctly

**Validation Steps**:
1. Generate report after all scans complete
2. Verify 3 distinct source IPs listed
3. Check scan types are different (SYN, UDP, ARP)
4. Confirm packet counts are accurate

---

### Test 12: Stealth Scan Combination

**Objective**: Test detection of combined scan techniques

**Commands**:
```bash
# Sequential scan types from same source
nmap -sF 192.168.1.100 -p 1-100
sleep 5
nmap -sX 192.168.1.100 -p 1-100
sleep 5
nmap -sN 192.168.1.100 -p 1-100
```

**Expected Results**:
- All three scan types detected
- Report shows multiple entries for same source IP
- Each scan type listed separately

---

## Validation Checklist

After each test, verify:

- [ ] Detection triggered (Info column shows alert)
- [ ] Correct scan type identified
- [ ] Appropriate confidence level assigned
- [ ] Source IP correctly captured
- [ ] Packet count accurate
- [ ] Display filters work correctly
- [ ] Report generation includes the scan
- [ ] No false positives from normal traffic

## Performance Testing

### Large PCAP File Test

**Objective**: Verify plugin handles large captures

**Steps**:
1. Create large PCAP with varied scan traffic
2. Load in Wireshark with plugin enabled
3. Monitor memory usage
4. Verify all scans detected
5. Generate report

**Expected Performance**:
- No crashes or freezes
- Report generation < 5 seconds for 100MB PCAP
- Memory usage remains reasonable

---

## False Positive Testing

### Test Legitimate Traffic

**Scenarios to Verify NO False Detections**:

1. **Normal Web Browsing**:
   ```bash
   # Should NOT trigger
   curl http://example.com
   wget http://example.com/page.html
   ```

2. **Legitimate Service Connections**:
   ```bash
   # SSH connections should NOT trigger
   ssh user@192.168.1.100
   
   # Database connections should NOT trigger
   mysql -h 192.168.1.100 -u user -p
   ```

3. **Application Traffic**:
   - DNS queries
   - Email (SMTP, IMAP, POP3)
   - File transfers (FTP, SFTP, SCP)

**Validation**: 
- Run these activities
- Generate report
- Verify NO scan detections for legitimate traffic
- If false positives occur, adjust thresholds

---

## Threshold Tuning Tests

### Test Different Threshold Values

**Low Threshold (Sensitive)**:
```lua
syn_threshold = 3
port_scan_threshold = 2
```

**High Threshold (Specific)**:
```lua
syn_threshold = 50
port_scan_threshold = 20
```

**Test Approach**:
1. Modify thresholds in plugin
2. Run same scan (e.g., `nmap -sS -p 1-10`)
3. Compare detection results
4. Find optimal balance for your network

---

## Integration Testing

### Test with Real-World PCAPs

Download sample PCAPs containing scans:

1. **Wireshark Sample Captures**: https://wiki.wireshark.org/SampleCaptures
2. **Malware Traffic Analysis**: https://malware-traffic-analysis.net
3. **PacketLife**: https://packetlife.net/captures

**Steps**:
1. Load PCAP in Wireshark
2. Plugin processes packets
3. Generate report
4. Manually verify detected scans match expected activity

---

## Troubleshooting Test Failures

### Scan Not Detected

**Debug Steps**:
1. Verify scan traffic is in capture
2. Check threshold not exceeded
3. Apply basic filter (e.g., `tcp.flags.syn == 1`)
4. Manually count packets vs threshold
5. Review plugin console output for errors

### Wrong Scan Type Identified

**Debug Steps**:
1. Examine packet TCP flags manually
2. Compare with scan type definitions
3. Check for conflicting detections
4. Review detection logic priority

### Performance Issues

**Debug Steps**:
1. Check PCAP size
2. Monitor CPU/memory during processing
3. Test with smaller time_window
4. Consider breaking large PCAPs into chunks

---

## Automated Testing Script

Here's a bash script to run multiple tests:

```bash
#!/bin/bash

TARGET="192.168.1.100"
PCAP_DIR="./test_pcaps"

mkdir -p $PCAP_DIR

echo "Starting Scan Detection Plugin Tests..."

# Test 1: SYN Scan
echo "[TEST 1] Running SYN Scan..."
sudo nmap -sS $TARGET -p 1-100 -oN ${PCAP_DIR}/syn_scan.txt

sleep 5

# Test 2: FIN Scan
echo "[TEST 2] Running FIN Scan..."
sudo nmap -sF $TARGET -p 1-50 -oN ${PCAP_DIR}/fin_scan.txt

sleep 5

# Test 3: XMAS Scan
echo "[TEST 3] Running XMAS Scan..."
sudo nmap -sX $TARGET -p 1-50 -oN ${PCAP_DIR}/xmas_scan.txt

sleep 5

# Test 4: NULL Scan
echo "[TEST 4] Running NULL Scan..."
sudo nmap -sN $TARGET -p 1-50 -oN ${PCAP_DIR}/null_scan.txt

sleep 5

# Test 5: ACK Scan
echo "[TEST 5] Running ACK Scan..."
sudo nmap -sA $TARGET -p 1-100 -oN ${PCAP_DIR}/ack_scan.txt

sleep 5

# Test 6: UDP Scan
echo "[TEST 6] Running UDP Scan..."
sudo nmap -sU $TARGET -p 53,161,500,67,68 -oN ${PCAP_DIR}/udp_scan.txt

sleep 5

# Test 7: ARP Scan
echo "[TEST 7] Running ARP Scan..."
sudo nmap -PR 192.168.1.0/24 -oN ${PCAP_DIR}/arp_scan.txt

echo "All tests complete. Review captures in Wireshark with plugin enabled."
echo "Generate report via: Tools > Scan Detector > Generate Report"
```

**Usage**:
1. Save as `test_scanner.sh`
2. Make executable: `chmod +x test_scanner.sh`
3. Run while capturing in Wireshark: `sudo ./test_scanner.sh`
4. Generate report when complete

---

## Expected Results Summary Table

| Test # | Scan Type | Nmap Command | Expected Detection | Confidence | Min Packets |
|--------|-----------|--------------|-------------------|------------|-------------|
| 1 | SYN | -sS | SYN Scan | HIGH | 10+ |
| 2 | FIN | -sF | FIN Scan | HIGH | 5+ |
| 3 | XMAS | -sX | XMAS Scan | HIGH | 5+ |
| 4 | NULL | -sN | NULL Scan | HIGH | 5+ |
| 5 | ACK | -sA | ACK Scan | MEDIUM | 5+ |
| 6 | UDP | -sU | UDP Scan | MEDIUM | 8+ |
| 7 | ARP | -PR | ARP Scan | HIGH | 5+ |
| 8 | Vuln | N/A | Nessus/OpenVAS/etc | HIGH | 1+ |

---

## Conclusion

This testing guide provides comprehensive validation of the scan detection plugin. Successful completion of these tests confirms:

✓ All major scan types detected correctly  
✓ Vulnerability scanners identified  
✓ False positive rate is acceptable  
✓ Performance is adequate  
✓ Display filters function properly  
✓ Reports generate accurate data  

Use these tests as a baseline and adjust thresholds based on your specific network environment and requirements.
