# Advanced Customization & Extension Guide

## Overview

This guide covers advanced customization options for the Wireshark Scan Detector plugin, including adding new scan types, custom signatures, and integration capabilities.

---

## Adding Custom Scan Detection

### Template for New Scan Type

```lua
-- Detect [Your Scan Type]
local function detect_custom_scan(pinfo, src_ip, dst_ip, custom_field)
    init_ip_tracking(src_ip)
    
    -- Your detection logic here
    if condition_detected then
        local key = dst_ip .. ":" .. tostring(custom_field)
        
        -- Track this scan activity
        if not scan_data.port_scans[src_ip].ports[key] then
            scan_data.port_scans[src_ip].ports[key] = "CUSTOM"
            scan_data.port_scans[src_ip].count = scan_data.port_scans[src_ip].count + 1
        end
        
        -- Check threshold
        if scan_data.port_scans[src_ip].count >= your_threshold then
            return true, "Custom Scan Type", "CONFIDENCE_LEVEL", "Detailed description"
        end
    end
    
    return false, nil, nil, nil
end
```

### Example: Detecting Masscan

Masscan is an extremely fast port scanner. Here's how to detect it:

```lua
-- Add to global data structures
scan_data.masscan_activity = {}

-- Detection function
local function detect_masscan(pinfo, src_ip, dst_ip, dst_port, timestamp)
    init_ip_tracking(src_ip)
    
    if not scan_data.masscan_activity[src_ip] then
        scan_data.masscan_activity[src_ip] = {
            ports = {},
            timestamps = {},
            count = 0
        }
    end
    
    local key = dst_ip .. ":" .. dst_port
    table.insert(scan_data.masscan_activity[src_ip].timestamps, timestamp)
    
    if not scan_data.masscan_activity[src_ip].ports[key] then
        scan_data.masscan_activity[src_ip].ports[key] = true
        scan_data.masscan_activity[src_ip].count = scan_data.masscan_activity[src_ip].count + 1
    end
    
    -- Masscan characteristics: Very high packet rate
    local time_count = #scan_data.masscan_activity[src_ip].timestamps
    if time_count >= 100 then
        -- Calculate packet rate (packets per second)
        local time_span = scan_data.masscan_activity[src_ip].timestamps[time_count] - 
                         scan_data.masscan_activity[src_ip].timestamps[1]
        
        if time_span > 0 then
            local pps = time_count / time_span
            
            -- Masscan typically operates at thousands of packets per second
            if pps > 1000 and scan_data.masscan_activity[src_ip].count > 50 then
                return true, "Masscan High-Speed Scan", "HIGH", 
                       string.format("Detected ultra-fast scanning: %.0f packets/sec to %d ports", 
                                   pps, scan_data.masscan_activity[src_ip].count)
            end
        end
    end
    
    return false, nil, nil, nil
end
```

**Integration**: Add this call in the main dissector function after other TCP checks.

---

## Custom Vulnerability Scanner Signatures

### Adding Commercial Scanners

```lua
local scanner_signatures = {
    user_agents = {
        -- Existing scanners...
        ["Nessus"] = "Nessus Vulnerability Scanner",
        ["OpenVAS"] = "OpenVAS Security Scanner",
        
        -- Add custom commercial scanners
        ["Qualys"] = "Qualys Web Application Scanner",
        ["Tenable"] = "Tenable.io Scanner",
        ["Rapid7"] = "Rapid7 Nexpose/InsightVM",
        ["AppScan"] = "IBM AppScan",
        ["WebInspect"] = "Micro Focus WebInspect",
        ["Netsparker"] = "Invicti/Netsparker Scanner",
        
        -- Add custom internal tools
        ["MyCompanyScanner"] = "Internal Security Tool",
        ["CustomPenTest"] = "Custom Penetration Testing Tool"
    },
    
    -- Add request path signatures
    request_paths = {
        ["/nessus_check"] = "Nessus",
        ["/openvas_test"] = "OpenVAS",
        ["/.git/HEAD"] = "Git Repository Scanner",
        ["/admin/config.php"] = "Web Vulnerability Scanner",
        ["/%2e%2e/"] = "Directory Traversal Scanner"
    }
}
```

### Enhanced Scanner Detection with Path Analysis

```lua
-- Enhanced vulnerability scanner detection
local function detect_vuln_scanner_enhanced(pinfo, user_agent, request_uri, src_ip)
    if not user_agent and not request_uri then 
        return false, nil, nil, nil 
    end
    
    init_ip_tracking(src_ip)
    
    -- Check User-Agent
    if user_agent then
        for signature, scanner_name in pairs(scanner_signatures.user_agents) do
            if string.find(user_agent, signature, 1, true) then
                scan_data.http_agents[src_ip] = scanner_name
                return true, scanner_name, "HIGH", 
                       string.format("Detected via User-Agent: %s", user_agent)
            end
        end
    end
    
    -- Check Request Path
    if request_uri then
        for path_sig, scanner_name in pairs(scanner_signatures.request_paths) do
            if string.find(request_uri, path_sig, 1, true) then
                return true, scanner_name .. " (Path Detection)", "MEDIUM",
                       string.format("Detected via request path: %s", request_uri)
            end
        end
        
        -- Detect common vulnerability scan patterns
        local vuln_patterns = {
            "sql", "union", "select", "' or ", "1=1",
            "../", "..\\", "%2e%2e",
            "<script", "alert(", "javascript:",
            "etc/passwd", "windows/system32"
        }
        
        for _, pattern in ipairs(vuln_patterns) do
            if string.find(string.lower(request_uri), pattern, 1, true) then
                return true, "Web Vulnerability Scanner (Pattern)", "MEDIUM",
                       string.format("Suspicious pattern in request: %s", pattern)
            end
        end
    end
    
    return false, nil, nil, nil
end
```

---

## Advanced Correlation Features

### Time-Based Attack Correlation

```lua
-- Track attack phases
local attack_phases = {}

local function correlate_attack_phases(src_ip, scan_type, timestamp)
    if not attack_phases[src_ip] then
        attack_phases[src_ip] = {
            phases = {},
            timeline = {}
        }
    end
    
    table.insert(attack_phases[src_ip].phases, scan_type)
    table.insert(attack_phases[src_ip].timeline, timestamp)
    
    -- Detect common attack patterns
    local phases = attack_phases[src_ip].phases
    local phase_count = #phases
    
    -- Classic attack pattern: ARP Scan -> SYN Scan -> Service Detection
    if phase_count >= 3 then
        if phases[phase_count - 2] == "ARP Scan" and
           phases[phase_count - 1] == "SYN Scan" and
           (string.find(phases[phase_count], "Scanner") or 
            string.find(phases[phase_count], "Service")) then
            
            return true, "Multi-Phase Attack", "CRITICAL",
                   "Detected reconnaissance -> port scan -> vulnerability scan sequence"
        end
    end
    
    return false, nil, nil, nil
end
```

### Geographic Tracking (if GeoIP available)

```lua
-- Track scanner geographic distribution
local scanner_locations = {}

local function track_scanner_location(src_ip, country_code)
    if not scanner_locations[country_code] then
        scanner_locations[country_code] = {
            ips = {},
            count = 0
        }
    end
    
    if not scanner_locations[country_code].ips[src_ip] then
        scanner_locations[country_code].ips[src_ip] = true
        scanner_locations[country_code].count = scanner_locations[country_code].count + 1
    end
    
    -- Alert on distributed scanning
    if scanner_locations[country_code].count > 10 then
        return true, "Distributed Scan Campaign", "HIGH",
               string.format("Multiple scanners from %s: %d unique IPs", 
                           country_code, scanner_locations[country_code].count)
    end
    
    return false, nil, nil, nil
end
```

---

## Custom Report Formats

### JSON Export Function

```lua
-- Export scan data as JSON
local function export_scan_data_json()
    local json_output = "{\n  \"scan_reports\": [\n"
    
    local first = true
    for key, report in pairs(scan_data.scan_reports) do
        if not first then
            json_output = json_output .. ",\n"
        end
        first = false
        
        json_output = json_output .. "    {\n"
        json_output = json_output .. string.format("      \"source_ip\": \"%s\",\n", report.source_ip)
        json_output = json_output .. string.format("      \"scan_type\": \"%s\",\n", report.scan_type)
        json_output = json_output .. string.format("      \"confidence\": \"%s\",\n", report.confidence)
        json_output = json_output .. string.format("      \"packet_count\": %d,\n", report.packet_count)
        json_output = json_output .. string.format("      \"first_seen\": %s,\n", tostring(report.first_seen))
        json_output = json_output .. string.format("      \"last_seen\": %s,\n", tostring(report.last_seen))
        json_output = json_output .. string.format("      \"details\": \"%s\"\n", report.details)
        json_output = json_output .. "    }"
    end
    
    json_output = json_output .. "\n  ],\n"
    json_output = json_output .. string.format("  \"total_scans\": %d\n", 
                                               table_length(scan_data.scan_reports))
    json_output = json_output .. "}\n"
    
    return json_output
end

-- Helper function to count table entries
local function table_length(t)
    local count = 0
    for _ in pairs(t) do count = count + 1 end
    return count
end

-- Menu item for JSON export
local function generate_json_report()
    local json_window = TextWindow.new("Scan Detection - JSON Export")
    local json_data = export_scan_data_json()
    json_window:set(json_data)
end

register_menu("Scan Detector/Export as JSON", generate_json_report, MENU_TOOLS_UNSORTED)
```

### CSV Export Function

```lua
-- Export scan data as CSV
local function export_scan_data_csv()
    local csv_output = "Source IP,Scan Type,Confidence,Packet Count,First Seen,Last Seen,Details\n"
    
    for key, report in pairs(scan_data.scan_reports) do
        csv_output = csv_output .. string.format("\"%s\",\"%s\",\"%s\",%d,%s,%s,\"%s\"\n",
            report.source_ip,
            report.scan_type,
            report.confidence,
            report.packet_count,
            tostring(report.first_seen),
            tostring(report.last_seen),
            report.details)
    end
    
    return csv_output
end

local function generate_csv_report()
    local csv_window = TextWindow.new("Scan Detection - CSV Export")
    local csv_data = export_scan_data_csv()
    csv_window:set(csv_data)
end

register_menu("Scan Detector/Export as CSV", generate_csv_report, MENU_TOOLS_UNSORTED)
```

---

## Integration with External Systems

### Syslog Integration

```lua
-- Send alerts to syslog
local function send_to_syslog(scan_type, src_ip, confidence, details)
    local syslog_message = string.format(
        "<134>1 %s %s ScanDetector - - - [Scan Detected] Type=%s Source=%s Confidence=%s Details=%s",
        os.date("!%Y-%m-%dT%H:%M:%SZ"),
        "wireshark-sensor",
        scan_type,
        src_ip,
        confidence,
        details
    )
    
    -- Note: Actual syslog sending requires socket library
    -- This is a template showing the message format
    print("SYSLOG: " .. syslog_message)
end
```

### SIEM Integration (Example: Splunk)

```lua
-- Format for Splunk HEC (HTTP Event Collector)
local function format_for_splunk(report)
    local splunk_event = {
        time = report.first_seen,
        source = "wireshark_scan_detector",
        sourcetype = "network_security:scan",
        event = {
            scan_type = report.scan_type,
            source_ip = report.source_ip,
            confidence = report.confidence,
            packet_count = report.packet_count,
            duration = report.last_seen - report.first_seen,
            details = report.details
        }
    }
    
    -- Convert to JSON and send to Splunk HEC endpoint
    -- Requires HTTP client library
    return splunk_event
end
```

---

## Performance Optimization

### Memory Management for Large Captures

```lua
-- Add cleanup function for old data
local function cleanup_old_data(current_time, max_age)
    max_age = max_age or 3600  -- Default: 1 hour
    
    -- Clean up old timestamps
    for ip, timestamps in pairs(scan_data.timestamps) do
        local new_timestamps = {}
        for _, ts in ipairs(timestamps) do
            if (current_time - ts) < max_age then
                table.insert(new_timestamps, ts)
            end
        end
        scan_data.timestamps[ip] = new_timestamps
    end
    
    -- Clean up old scan reports
    for key, report in pairs(scan_data.scan_reports) do
        if (current_time - report.last_seen) > max_age then
            scan_data.scan_reports[key] = nil
        end
    end
end

-- Call this periodically in dissector
-- if packet_count % 10000 == 0 then
--     cleanup_old_data(pinfo.abs_ts, 3600)
-- end
```

### Efficient Port Tracking

```lua
-- Use bit arrays for port tracking instead of tables
local function init_port_bitmap()
    return {
        bitmap = {},  -- Array of 2048 integers (65536 bits / 32 bits per integer)
        count = 0
    }
end

local function set_port_bit(bitmap, port)
    local idx = math.floor(port / 32) + 1
    local bit = port % 32
    
    if not bitmap.bitmap[idx] then
        bitmap.bitmap[idx] = 0
    end
    
    local mask = bit.lshift(1, bit)
    local old_val = bitmap.bitmap[idx]
    bitmap.bitmap[idx] = bit.bor(bitmap.bitmap[idx], mask)
    
    -- Increment count only if bit wasn't set before
    if old_val ~= bitmap.bitmap[idx] then
        bitmap.count = bitmap.count + 1
    end
end

local function is_port_set(bitmap, port)
    local idx = math.floor(port / 32) + 1
    local bit = port % 32
    
    if not bitmap.bitmap[idx] then
        return false
    end
    
    local mask = bit.lshift(1, bit)
    return bit.band(bitmap.bitmap[idx], mask) ~= 0
end
```

---

## Advanced Filtering Examples

### Complex Display Filters

```lua
-- These can be used in Wireshark's display filter bar

-- Find all high-confidence scans from specific subnet
scandetector.confidence == "HIGH" && ip.src == 10.0.0.0/8

-- Find scans targeting specific service
scandetector && tcp.dstport == 445

-- Combine with time range
scandetector.type == "SYN Scan" && frame.time >= "2024-01-01 00:00:00"

-- Find vulnerability scanners only
scandetector.type contains "Scanner"

-- Exclude specific IP from scan detection
scandetector && !(ip.src == 192.168.1.100)
```

---

## Custom Alerting Rules

### Rule-Based Alert System

```lua
-- Define custom alert rules
local alert_rules = {
    {
        name = "Critical Infrastructure Scan",
        condition = function(scan)
            -- Alert on scans from external IPs to DMZ servers
            return string.match(scan.source_ip, "^(%d+)%.") ~= "192" and
                   scan.confidence == "HIGH"
        end,
        severity = "CRITICAL",
        action = function(scan)
            print("ALERT: External scan detected!")
            -- Could trigger external notification
        end
    },
    {
        name = "Insider Threat",
        condition = function(scan)
            -- Alert on internal scanning activity
            return string.match(scan.source_ip, "^192%.168%.") and
                   scan.packet_count > 1000
        end,
        severity = "HIGH",
        action = function(scan)
            print("ALERT: Internal scanning detected!")
        end
    }
}

-- Check rules when scan is detected
local function check_alert_rules(scan)
    for _, rule in ipairs(alert_rules) do
        if rule.condition(scan) then
            rule.action(scan)
            return true, rule.severity, rule.name
        end
    end
    return false, nil, nil
end
```

---

## Statistical Analysis

### Port Distribution Analysis

```lua
-- Analyze which ports are most frequently scanned
local function analyze_port_distribution()
    local port_stats = {}
    
    for ip, data in pairs(scan_data.port_scans) do
        for target, scan_type in pairs(data.ports) do
            local port = string.match(target, ":(%d+)$")
            if port then
                port_stats[port] = (port_stats[port] or 0) + 1
            end
        end
    end
    
    -- Sort by frequency
    local sorted_ports = {}
    for port, count in pairs(port_stats) do
        table.insert(sorted_ports, {port = port, count = count})
    end
    
    table.sort(sorted_ports, function(a, b) return a.count > b.count end)
    
    return sorted_ports
end

-- Add to report generation
local function generate_enhanced_report()
    local report = generate_scan_report()  -- Original report
    
    -- Add port distribution
    report = report .. "\n\nMOST TARGETED PORTS:\n"
    report = report .. string.rep("-", 80) .. "\n"
    
    local port_dist = analyze_port_distribution()
    for i = 1, math.min(10, #port_dist) do
        report = report .. string.format("Port %s: %d scan attempts\n", 
                                        port_dist[i].port, port_dist[i].count)
    end
    
    return report
end
```

---

## Debugging and Logging

### Enable Debug Logging

```lua
-- Debug configuration
local debug_config = {
    enabled = false,  -- Set to true for debugging
    log_detections = true,
    log_packets = false,
    log_file = nil  -- Set to file path if needed
}

local function debug_log(message)
    if debug_config.enabled then
        local timestamp = os.date("%Y-%m-%d %H:%M:%S")
        local log_msg = string.format("[%s] %s", timestamp, message)
        print(log_msg)
        
        if debug_config.log_file then
            local f = io.open(debug_config.log_file, "a")
            if f then
                f:write(log_msg .. "\n")
                f:close()
            end
        end
    end
end

-- Use in detection functions
-- debug_log(string.format("SYN scan check: %s -> %s:%d", src_ip, dst_ip, dst_port))
```

---

## Conclusion

This advanced customization guide provides templates and examples for:

✓ Adding new scan detection types  
✓ Custom vulnerability scanner signatures  
✓ Advanced correlation and analysis  
✓ Multiple export formats (JSON, CSV)  
✓ SIEM integration templates  
✓ Performance optimizations  
✓ Custom alerting rules  
✓ Statistical analysis features  

Use these examples as building blocks to tailor the plugin to your specific security monitoring needs. Remember to test thoroughly after any modifications and adjust detection thresholds based on your network environment.
