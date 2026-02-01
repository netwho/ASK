-- Wireshark Scan Detection Plugin
-- Detects Nmap scans, vulnerability scanners (OpenVAS, Nessus, etc.)
-- Version: 0.1.0

-- Register plugin info with Wireshark
set_plugin_info({
    version = "0.1.0",
    author = "Walter Hofstetter",
    description = "Detects network scans including Nmap, OpenVAS, Nessus and other vulnerability scanners",
    repository = "https://github.com/netwho/ScanDetector"
})

-- Protocol declaration
local scan_detector = Proto("ScanDetector", "Network Scan Detection and Analysis")

-- Create fields for our protocol
local f_scan_type = ProtoField.string("scandetector.type", "Scan Type")
local f_scan_source = ProtoField.string("scandetector.source", "Scan Source IP")
local f_scan_confidence = ProtoField.string("scandetector.confidence", "Detection Confidence")
local f_scan_details = ProtoField.string("scandetector.details", "Scan Details")

scan_detector.fields = {f_scan_type, f_scan_source, f_scan_confidence, f_scan_details}

-- Global data structures for tracking scan activity
local scan_data = {
    tcp_syn = {},           -- Track SYN packets per source IP
    tcp_connections = {},   -- Track connection states
    port_scans = {},        -- Track port scanning activity
    arp_scans = {},         -- Track ARP scan activity
    udp_activity = {},      -- Track UDP scanning
    timestamps = {},        -- Track packet timestamps for timing analysis
    http_agents = {},       -- Track HTTP User-Agents for scanner detection
    scan_reports = {},      -- Store detected scans
    dns_cache = {},         -- Track IP to hostname mappings
    nmap_indicators = {}    -- Track NMAP-specific indicators per IP
}

-- Pre-create all Field extractors at script load time (MUST be before dissector is called)
-- IP address fields (these bypass name resolution and get raw IPs)
local ip_src_field = Field.new("ip.src")
local ip_dst_field = Field.new("ip.dst")
local ipv6_src_field = Field.new("ipv6.src")
local ipv6_dst_field = Field.new("ipv6.dst")
-- TCP/UDP fields
local tcp_flags_field = Field.new("tcp.flags")
local tcp_dstport_field = Field.new("tcp.dstport")
local tcp_window_field = Field.new("tcp.window_size_value")
local udp_dstport_field = Field.new("udp.dstport")
-- ARP fields
local arp_opcode_field = Field.new("arp.opcode")
local arp_src_field = Field.new("arp.src.proto_ipv4")
local arp_target_field = Field.new("arp.dst.proto_ipv4")
-- HTTP fields
local http_user_agent_field = Field.new("http.user_agent")
-- DNS fields for hostname resolution tracking
local dns_qry_name_field = Field.new("dns.qry.name")
local dns_a_field = Field.new("dns.a")
local dns_resp_name_field = Field.new("dns.resp.name")

-- Configuration
local config = {
    syn_threshold = 10,              -- Number of SYN packets to consider scanning
    port_scan_threshold = 5,         -- Number of different ports to trigger detection
    ack_scan_threshold = 15,         -- Number of unsolicited ACK packets to trigger detection (higher to reduce false positives)
    ack_min_destinations = 2,        -- Minimum number of different destinations for ACK scan detection (reduces false positives)
    time_window = 60,                -- Time window in seconds for scan detection
    arp_scan_threshold = 5,          -- Number of ARP requests to consider scanning
    udp_scan_threshold = 8,          -- Number of UDP packets to different ports
    source_width = 15,               -- Fixed width for source IP column (max IPv4 = 15)
    scan_type_width = 30             -- Fixed width for scan type column
}

-- Known vulnerability scanner signatures
local scanner_signatures = {
    user_agents = {
        ["Nmap Scripting Engine"] = "Nmap NSE Vulnerability Scanner",
        ["nmap.org/book/nse.html"] = "Nmap NSE Vulnerability Scanner",
        ["Nessus"] = "Nessus Vulnerability Scanner",
        ["OpenVAS"] = "OpenVAS Security Scanner",
        ["Nikto"] = "Nikto Web Scanner",
        ["Acunetix"] = "Acunetix Web Vulnerability Scanner",
        ["Burp"] = "Burp Suite Scanner",
        ["OWASP ZAP"] = "OWASP ZAP Scanner",
        ["Qualys"] = "Qualys Scanner",
        ["Rapid7"] = "Rapid7 Nexpose/InsightVM"
    }
}

-- NMAP-specific detection patterns
local nmap_patterns = {
    -- NMAP often uses specific TCP window sizes
    common_windows = {63, 1024, 2048, 3072, 4096, 5840, 8192, 16384},
    -- NMAP timing characteristics (packets per second)
    timing_threshold = 100  -- More than 100 packets/sec suggests fast scanning
}

-- Helper function to check if string is an IP address
local function is_ip_address(str)
    if not str or #str == 0 then
        return false
    end
    -- IPv4 check: only digits and dots, proper format
    if str:match("^%d+%.%d+%.%d+%.%d+$") then
        return true
    end
    -- IPv6 check: contains colons and only hex digits/colons
    -- Must have at least one colon to be IPv6
    if str:find(":") and str:match("^[%x:]+$") then
        return true
    end
    return false
end

-- Helper function to format IP to fixed width (max 15 chars for IPv4)
local function format_ip(ip_str, width)
    width = width or config.source_width
    if #ip_str > width then
        return ip_str:sub(1, width)
    end
    return ip_str .. string.rep(" ", width - #ip_str)
end

-- Helper function to format scan type to fixed width and truncate if needed
local function format_scan_type(scan_type_str, width)
    width = width or config.scan_type_width
    if #scan_type_str > width then
        return scan_type_str:sub(1, width)
    end
    return scan_type_str .. string.rep(" ", width - #scan_type_str)
end

-- Helper function to add DNS resolution to cache
local function cache_dns_resolution(ip, hostname)
    if ip and hostname and ip ~= hostname and is_ip_address(ip) then
        scan_data.dns_cache[ip] = hostname
    end
end

-- Helper function to get hostname for an IP (from cache)
local function get_hostname(ip)
    return scan_data.dns_cache[ip]
end

-- Helper function to get current time key (rounded to time window)
local function get_time_window(timestamp)
    return math.floor(timestamp / config.time_window)
end

-- Helper function to check if IP is in our tracking
local function init_ip_tracking(ip)
    if not scan_data.tcp_syn[ip] then
        scan_data.tcp_syn[ip] = {}
    end
    if not scan_data.tcp_connections[ip] then
        scan_data.tcp_connections[ip] = {}
    end
    if not scan_data.port_scans[ip] then
        scan_data.port_scans[ip] = {ports = {}, count = 0, first_seen = 0, destinations = {}}  -- Track destinations for ACK scans
    end
    if not scan_data.arp_scans[ip] then
        scan_data.arp_scans[ip] = {targets = {}, count = 0}
    end
    if not scan_data.udp_activity[ip] then
        scan_data.udp_activity[ip] = {ports = {}, count = 0}
    end
    if not scan_data.timestamps[ip] then
        scan_data.timestamps[ip] = {}
    end
    if not scan_data.nmap_indicators[ip] then
        scan_data.nmap_indicators[ip] = {
            window_sizes = {},      -- Track TCP window sizes seen
            packet_times = {},      -- Track packet timestamps for timing analysis
            nmap_likelihood = 0     -- Score 0-100 for NMAP likelihood
        }
    end
end

-- Helper function to check for NMAP indicators
local function check_nmap_indicators(src_ip, tcp_window)
    if not scan_data.nmap_indicators[src_ip] then
        return false
    end

    local indicators = scan_data.nmap_indicators[src_ip]
    local nmap_score = 0

    -- Check if TCP window size matches common NMAP values
    if tcp_window then
        indicators.window_sizes[tcp_window] = true
        for _, common_win in ipairs(nmap_patterns.common_windows) do
            if tcp_window == common_win then
                nmap_score = nmap_score + 30
                break
            end
        end
    end

    -- Check packet timing (rapid sequential scans are typical of NMAP)
    local packet_count = 0
    for _ in pairs(indicators.packet_times) do
        packet_count = packet_count + 1
    end

    if packet_count > 50 then
        nmap_score = nmap_score + 40
    elseif packet_count > 20 then
        nmap_score = nmap_score + 20
    end

    -- Check for variety of window sizes (NMAP often varies these)
    local window_variety = 0
    for _ in pairs(indicators.window_sizes) do
        window_variety = window_variety + 1
    end

    if window_variety >= 3 then
        nmap_score = nmap_score + 30
    end

    indicators.nmap_likelihood = nmap_score

    return nmap_score >= 50  -- 50% or higher indicates likely NMAP
end

-- Helper function to get NMAP likelihood for an IP
local function get_nmap_likelihood(src_ip)
    if scan_data.nmap_indicators[src_ip] then
        return scan_data.nmap_indicators[src_ip].nmap_likelihood
    end
    return 0
end

-- Helper function to get base scan type (without "Nmap" prefix)
local function get_base_scan_type(scan_type)
    if scan_type:sub(1, 5) == "Nmap " then
        return scan_type:sub(6)  -- Remove "Nmap " prefix
    end
    return scan_type
end

-- Helper function to get display scan type (with "Nmap" prefix if applicable)
local function get_display_scan_type(base_type, src_ip)
    if get_nmap_likelihood(src_ip) >= 50 then
        return "Nmap " .. base_type
    end
    return base_type
end

-- Detect TCP SYN scan
local function detect_syn_scan(pinfo, tcp_flags_val, src_ip, dst_ip, dst_port, tcp_window, timestamp)
    -- SYN flag set, ACK flag not set
    if bit.band(tcp_flags_val, 0x02) ~= 0 and bit.band(tcp_flags_val, 0x10) == 0 then
        init_ip_tracking(src_ip)

        -- Track NMAP indicators
        if tcp_window and scan_data.nmap_indicators[src_ip] then
            table.insert(scan_data.nmap_indicators[src_ip].packet_times, timestamp)
            check_nmap_indicators(src_ip, tcp_window)
        end

        local key = dst_ip .. ":" .. dst_port
        scan_data.tcp_syn[src_ip][key] = (scan_data.tcp_syn[src_ip][key] or 0) + 1

        -- Count unique destination combinations
        local unique_dests = 0
        for _ in pairs(scan_data.tcp_syn[src_ip]) do
            unique_dests = unique_dests + 1
        end

        if unique_dests >= config.syn_threshold then
            return true, "SYN Scan", "HIGH", string.format("Detected %d SYN packets to different targets", unique_dests)
        end
    end
    return false, nil, nil, nil
end

-- Detect TCP FIN scan
local function detect_fin_scan(pinfo, tcp_flags_val, src_ip, dst_ip, dst_port, tcp_window, timestamp)
    -- Only FIN flag set (0x01)
    if tcp_flags_val == 0x01 then
        init_ip_tracking(src_ip)

        -- Track NMAP indicators
        if tcp_window and scan_data.nmap_indicators[src_ip] then
            table.insert(scan_data.nmap_indicators[src_ip].packet_times, timestamp)
            check_nmap_indicators(src_ip, tcp_window)
        end

        local key = dst_ip .. ":" .. dst_port
        if not scan_data.port_scans[src_ip].ports[key] then
            scan_data.port_scans[src_ip].ports[key] = "FIN"
            scan_data.port_scans[src_ip].count = scan_data.port_scans[src_ip].count + 1
        end

        if scan_data.port_scans[src_ip].count >= config.port_scan_threshold then
            return true, "FIN Scan", "HIGH", string.format("Detected FIN packets to %d different ports", scan_data.port_scans[src_ip].count)
        end
    end
    return false, nil, nil, nil
end

-- Detect TCP XMAS scan
local function detect_xmas_scan(pinfo, tcp_flags_val, src_ip, dst_ip, dst_port, tcp_window, timestamp)
    -- FIN, PSH, URG flags set (0x29 = 0x01 | 0x08 | 0x20)
    local xmas_flags = 0x29
    if bit.band(tcp_flags_val, xmas_flags) == xmas_flags then
        init_ip_tracking(src_ip)

        -- Track NMAP indicators
        if tcp_window and scan_data.nmap_indicators[src_ip] then
            table.insert(scan_data.nmap_indicators[src_ip].packet_times, timestamp)
            check_nmap_indicators(src_ip, tcp_window)
        end

        local key = dst_ip .. ":" .. dst_port
        if not scan_data.port_scans[src_ip].ports[key] then
            scan_data.port_scans[src_ip].ports[key] = "XMAS"
            scan_data.port_scans[src_ip].count = scan_data.port_scans[src_ip].count + 1
        end

        if scan_data.port_scans[src_ip].count >= config.port_scan_threshold then
            return true, "XMAS Scan", "HIGH", string.format("Detected XMAS packets to %d different ports", scan_data.port_scans[src_ip].count)
        end
    end
    return false, nil, nil, nil
end

-- Detect TCP NULL scan
local function detect_null_scan(pinfo, tcp_flags_val, src_ip, dst_ip, dst_port, tcp_window, timestamp)
    -- No flags set
    if tcp_flags_val == 0 then
        init_ip_tracking(src_ip)

        -- Track NMAP indicators
        if tcp_window and scan_data.nmap_indicators[src_ip] then
            table.insert(scan_data.nmap_indicators[src_ip].packet_times, timestamp)
            check_nmap_indicators(src_ip, tcp_window)
        end

        local key = dst_ip .. ":" .. dst_port
        if not scan_data.port_scans[src_ip].ports[key] then
            scan_data.port_scans[src_ip].ports[key] = "NULL"
            scan_data.port_scans[src_ip].count = scan_data.port_scans[src_ip].count + 1
        end

        if scan_data.port_scans[src_ip].count >= config.port_scan_threshold then
            return true, "NULL Scan", "HIGH", string.format("Detected NULL packets to %d different ports", scan_data.port_scans[src_ip].count)
        end
    end
    return false, nil, nil, nil
end

-- Detect TCP ACK scan
local function detect_ack_scan(pinfo, tcp_flags_val, src_ip, dst_ip, dst_port, tcp_window, timestamp)
    -- Only ACK flag set, no SYN
    if bit.band(tcp_flags_val, 0x10) ~= 0 and bit.band(tcp_flags_val, 0x02) == 0 then
        init_ip_tracking(src_ip)

        -- Track NMAP indicators
        if tcp_window and scan_data.nmap_indicators[src_ip] then
            table.insert(scan_data.nmap_indicators[src_ip].packet_times, timestamp)
            check_nmap_indicators(src_ip, tcp_window)
        end

        local conn_key = dst_ip .. ":" .. dst_port
        -- Check if this is part of an established connection
        if not scan_data.tcp_connections[src_ip][conn_key] then
            local key = dst_ip .. ":" .. dst_port
            
            -- Track unique ports
            if not scan_data.port_scans[src_ip].ports[key] then
                scan_data.port_scans[src_ip].ports[key] = "ACK"
                scan_data.port_scans[src_ip].count = scan_data.port_scans[src_ip].count + 1
            end
            
            -- Track unique destinations for ACK scans (to reduce false positives)
            if not scan_data.port_scans[src_ip].destinations[dst_ip] then
                scan_data.port_scans[src_ip].destinations[dst_ip] = true
            end
            
            -- Count unique destinations
            local unique_destinations = 0
            for _ in pairs(scan_data.port_scans[src_ip].destinations) do
                unique_destinations = unique_destinations + 1
            end
            
            -- Only trigger if:
            -- 1. Threshold of ACK packets reached (higher threshold to reduce false positives)
            -- 2. ACKs are sent to multiple destinations (reduces false positives from single-host retransmissions)
            if scan_data.port_scans[src_ip].count >= config.ack_scan_threshold and
               unique_destinations >= config.ack_min_destinations then
                return true, "ACK Scan", "MEDIUM", 
                       string.format("Detected unsolicited ACK packets to %d different ports across %d destinations", 
                                   scan_data.port_scans[src_ip].count, unique_destinations)
            end
        end
    end
    return false, nil, nil, nil
end

-- Detect ARP scan
local function detect_arp_scan(pinfo, src_ip, arp_opcode, arp_target)
    if arp_opcode == 1 then -- ARP request
        init_ip_tracking(src_ip)

        if arp_target and not scan_data.arp_scans[src_ip].targets[arp_target] then
            scan_data.arp_scans[src_ip].targets[arp_target] = true
            scan_data.arp_scans[src_ip].count = scan_data.arp_scans[src_ip].count + 1
        end

        if scan_data.arp_scans[src_ip].count >= config.arp_scan_threshold then
            return true, "ARP Scan", "HIGH", string.format("Detected ARP requests to %d different IPs", scan_data.arp_scans[src_ip].count)
        end
    end
    return false, nil, nil, nil
end

-- Detect UDP scan
local function detect_udp_scan(pinfo, src_ip, dst_ip, dst_port)
    init_ip_tracking(src_ip)

    local key = dst_ip .. ":" .. dst_port
    if not scan_data.udp_activity[src_ip].ports[key] then
        scan_data.udp_activity[src_ip].ports[key] = true
        scan_data.udp_activity[src_ip].count = scan_data.udp_activity[src_ip].count + 1
    end

    if scan_data.udp_activity[src_ip].count >= config.udp_scan_threshold then
        return true, "UDP Scan", "MEDIUM", string.format("Detected UDP packets to %d different ports", scan_data.udp_activity[src_ip].count)
    end

    return false, nil, nil, nil
end

-- Detect vulnerability scanners by HTTP User-Agent
local function detect_vuln_scanner(pinfo, user_agent, src_ip)
    if not user_agent then return false, nil, nil, nil end

    for signature, scanner_name in pairs(scanner_signatures.user_agents) do
        if string.find(user_agent, signature, 1, true) then
            init_ip_tracking(src_ip)
            scan_data.http_agents[src_ip] = scanner_name
            return true, scanner_name, "HIGH", string.format("Detected via User-Agent: %s", user_agent)
        end
    end

    return false, nil, nil, nil
end

-- Process DNS responses to build IP-to-hostname cache
local function process_dns_response()
    local dns_a = dns_a_field()
    local dns_name = dns_qry_name_field()

    if dns_a and dns_name then
        local ip = tostring(dns_a)
        local hostname = tostring(dns_name)
        cache_dns_resolution(ip, hostname)
    end
end

-- Extract numeric IP address from packet headers, bypassing name resolution
local function extract_ip_addresses()
    local src_ip = nil
    local dst_ip = nil

    -- Try IPv4 first (most common)
    local ip_src = ip_src_field()
    local ip_dst = ip_dst_field()

    if ip_src and ip_dst then
        src_ip = tostring(ip_src)
        dst_ip = tostring(ip_dst)
        return src_ip, dst_ip
    end

    -- Try IPv6
    local ipv6_src = ipv6_src_field()
    local ipv6_dst = ipv6_dst_field()

    if ipv6_src and ipv6_dst then
        src_ip = tostring(ipv6_src)
        dst_ip = tostring(ipv6_dst)
        return src_ip, dst_ip
    end

    -- For ARP packets, use ARP source
    local arp_src = arp_src_field()
    if arp_src then
        src_ip = tostring(arp_src)
        dst_ip = "0.0.0.0"  -- ARP doesn't have a specific destination IP in the same way
        return src_ip, dst_ip
    end

    -- Fallback: return nil (packet type we don't handle)
    return nil, nil
end

-- Main dissector function
function scan_detector.dissector(buffer, pinfo, tree)
    -- Get packet timestamp
    local timestamp = pinfo.abs_ts

    -- Process any DNS responses to build our hostname cache
    process_dns_response()

    -- Extract IP addresses from packet headers (bypasses name resolution)
    local src_ip, dst_ip = extract_ip_addresses()

    -- If we couldn't extract IPs, skip this packet
    if not src_ip or not dst_ip then
        return
    end

    -- Build DNS cache by comparing pinfo (which may have hostnames) with actual IPs
    local src_display = tostring(pinfo.src)
    local dst_display = tostring(pinfo.dst)

    -- DEBUG: Print first time we see IP extraction difference
    if src_display ~= src_ip and not is_ip_address(src_display) then
        if not scan_data.dns_cache[src_ip] then
            print(string.format("DEBUG: Extracted IP %s from display name %s", src_ip, src_display))
        end
        cache_dns_resolution(src_ip, src_display)
    end
    if dst_display ~= dst_ip and not is_ip_address(dst_display) then
        cache_dns_resolution(dst_ip, dst_display)
    end

    local detected = false
    local scan_type = nil
    local confidence = nil
    local details = nil

    -- Check for TCP-based scans
    local tcp_flags = tcp_flags_field()

    if tcp_flags then
        local tcp_flags_val = tcp_flags.value  -- Extract numeric value from FieldInfo
        local dst_port = tcp_dstport_field()
        local tcp_window = tcp_window_field()
        local tcp_win_val = tcp_window and tcp_window.value or nil

        if dst_port then
            dst_port = dst_port.value

            -- Check various TCP scan types
            local det, typ, conf, det_details

            det, typ, conf, det_details = detect_syn_scan(pinfo, tcp_flags_val, src_ip, dst_ip, dst_port, tcp_win_val, timestamp)
            if det then detected, scan_type, confidence, details = det, typ, conf, det_details end

            det, typ, conf, det_details = detect_fin_scan(pinfo, tcp_flags_val, src_ip, dst_ip, dst_port, tcp_win_val, timestamp)
            if det then detected, scan_type, confidence, details = det, typ, conf, det_details end

            det, typ, conf, det_details = detect_xmas_scan(pinfo, tcp_flags_val, src_ip, dst_ip, dst_port, tcp_win_val, timestamp)
            if det then detected, scan_type, confidence, details = det, typ, conf, det_details end

            det, typ, conf, det_details = detect_null_scan(pinfo, tcp_flags_val, src_ip, dst_ip, dst_port, tcp_win_val, timestamp)
            if det then detected, scan_type, confidence, details = det, typ, conf, det_details end

            det, typ, conf, det_details = detect_ack_scan(pinfo, tcp_flags_val, src_ip, dst_ip, dst_port, tcp_win_val, timestamp)
            if det then detected, scan_type, confidence, details = det, typ, conf, det_details end
        end
    end

    -- Check for UDP scans
    local udp_dstport = udp_dstport_field()

    if udp_dstport then
        local det, typ, conf, det_details = detect_udp_scan(pinfo, src_ip, dst_ip, udp_dstport.value)
        if det then detected, scan_type, confidence, details = det, typ, conf, det_details end
    end

    -- Check for ARP scans
    local arp_opcode = arp_opcode_field()

    if arp_opcode then
        local arp_target = arp_target_field()
        local target_ip = arp_target and tostring(arp_target) or nil

        local det, typ, conf, det_details = detect_arp_scan(pinfo, src_ip, arp_opcode.value, target_ip)
        if det then detected, scan_type, confidence, details = det, typ, conf, det_details end
    end

    -- Check for vulnerability scanner User-Agents
    local http_user_agent = http_user_agent_field()

    if http_user_agent then
        local det, typ, conf, det_details = detect_vuln_scanner(pinfo, tostring(http_user_agent), src_ip)
        if det then detected, scan_type, confidence, details = det, typ, conf, det_details end
    end

    -- If scan detected, add to protocol tree and store report
    if detected then
        local subtree = tree:add(scan_detector, buffer())
        subtree:add(f_scan_type, scan_type)
        subtree:add(f_scan_source, src_ip)
        subtree:add(f_scan_confidence, confidence)
        subtree:add(f_scan_details, details)

        -- FIXED: Use base scan type for report key to prevent duplicates when NMAP attribution changes
        local base_type = get_base_scan_type(scan_type)
        local report_key = src_ip .. "_" .. base_type

        if not scan_data.scan_reports[report_key] then
            -- DEBUG: Print when creating new scan report
            print(string.format("DEBUG: Creating scan report with key='%s', src_ip='%s', base_type='%s', hostname='%s'",
                report_key, src_ip, base_type, tostring(get_hostname(src_ip))))

            scan_data.scan_reports[report_key] = {
                source_ip = src_ip,  -- Always store the IP address
                hostname = get_hostname(src_ip),  -- Store hostname separately
                base_scan_type = base_type,  -- Store base type (without "Nmap" prefix)
                confidence = confidence,
                first_seen = timestamp,
                last_seen = timestamp,
                packet_count = 0,
                details = details
            }
        end

        -- Update hostname if we learned it later
        if not scan_data.scan_reports[report_key].hostname then
            scan_data.scan_reports[report_key].hostname = get_hostname(src_ip)
        end

        scan_data.scan_reports[report_key].last_seen = timestamp
        scan_data.scan_reports[report_key].packet_count = scan_data.scan_reports[report_key].packet_count + 1

        -- Update info column with dynamically generated display name
        local display_type = get_display_scan_type(base_type, src_ip)
        local current_info = tostring(pinfo.cols.info)
        pinfo.cols.info = current_info .. " [" .. display_type .. " DETECTED]"
    end
end

-- Register post-dissector
register_postdissector(scan_detector)

-- Menu action to generate scan report
local function generate_scan_report()
    local report_window = TextWindow.new("Network Scan Detection Report")

    local report_text = "=" .. string.rep("=", 93) .. "\n"
    report_text = report_text .. "  NETWORK SCAN DETECTION REPORT\n"
    report_text = report_text .. "=" .. string.rep("=", 93) .. "\n\n"

    local scan_count = 0
    for _ in pairs(scan_data.scan_reports) do
        scan_count = scan_count + 1
    end

    report_text = report_text .. string.format("Total Scans Detected: %d\n\n", scan_count)

    if scan_count == 0 then
        report_text = report_text .. "No scanning activity detected in current capture.\n"
    else
        -- Table header with fixed-width columns (IP: 15, Scan Type: 30, Confidence: 10, Pkts: 6)
        report_text = report_text .. string.format("%-15s %-30s %-10s %-6s %s\n",
            "Source IP", "Scan Type", "Confidence", "Pkts", "Details")
        report_text = report_text .. string.rep("-", 93) .. "\n"

        for key, report in pairs(scan_data.scan_reports) do
            -- FIXED: Always display IP address in summary table (no truncation needed for IPs)
            local formatted_ip = format_ip(report.source_ip, 15)
            -- Dynamically generate display name based on current NMAP score
            local display_type = get_display_scan_type(report.base_scan_type, report.source_ip)
            local formatted_scan_type = format_scan_type(display_type, 30)
            report_text = report_text .. string.format("%-15s %-30s %-10s %-6d %s\n",
                formatted_ip,
                formatted_scan_type,
                report.confidence,
                report.packet_count,
                report.details)
        end

        report_text = report_text .. "\n" .. string.rep("-", 93) .. "\n\n"

        -- Detailed breakdown by scan type with DNS resolution info
        report_text = report_text .. "DETAILED SCAN ANALYSIS:\n"
        report_text = report_text .. string.rep("-", 93) .. "\n"

        for key, report in pairs(scan_data.scan_reports) do
            -- FIXED: Show IP address in the title, hostname on separate line
            -- Dynamically generate display name based on current NMAP score
            local display_type = get_display_scan_type(report.base_scan_type, report.source_ip)
            report_text = report_text .. string.format("\n[%s] %s\n", display_type, report.source_ip)

            -- Add hostname resolution if available
            if report.hostname then
                report_text = report_text .. string.format("  Hostname:   %s\n", report.hostname)
            else
                local cached_hostname = get_hostname(report.source_ip)
                if cached_hostname then
                    report_text = report_text .. string.format("  Hostname:   %s\n", cached_hostname)
                else
                    report_text = report_text .. "  Hostname:   (not resolved)\n"
                end
            end

            report_text = report_text .. string.format("  First Seen: %s\n", tostring(report.first_seen))
            report_text = report_text .. string.format("  Last Seen:  %s\n", tostring(report.last_seen))
            report_text = report_text .. string.format("  Packets:    %d\n", report.packet_count)
            report_text = report_text .. string.format("  Confidence: %s\n", report.confidence)

            -- Add NMAP likelihood if available
            local nmap_likelihood = get_nmap_likelihood(report.source_ip)
            if nmap_likelihood > 0 then
                report_text = report_text .. string.format("  Nmap Score: %d%% ", nmap_likelihood)
                if nmap_likelihood >= 70 then
                    report_text = report_text .. "(Very likely Nmap)\n"
                elseif nmap_likelihood >= 50 then
                    report_text = report_text .. "(Likely Nmap)\n"
                else
                    report_text = report_text .. "(Possibly Nmap)\n"
                end
            end

            report_text = report_text .. string.format("  Details:    %s\n", report.details)
        end

        -- DNS Resolution Cache section
        report_text = report_text .. "\n" .. string.rep("=", 93) .. "\n"
        report_text = report_text .. "DNS RESOLUTION CACHE:\n"
        report_text = report_text .. string.rep("-", 93) .. "\n"

        local dns_count = 0
        for ip, hostname in pairs(scan_data.dns_cache) do
            report_text = report_text .. string.format("  %-15s -> %s\n", ip, hostname)
            dns_count = dns_count + 1
        end

        if dns_count == 0 then
            report_text = report_text .. "  (No DNS resolutions captured in this session)\n"
        end

        -- Statistics section
        report_text = report_text .. "\n" .. string.rep("=", 93) .. "\n"
        report_text = report_text .. "STATISTICS:\n"
        report_text = report_text .. string.rep("-", 93) .. "\n"

        local scan_type_counts = {}
        for key, report in pairs(scan_data.scan_reports) do
            -- Use dynamic display name for statistics
            local display_type = get_display_scan_type(report.base_scan_type, report.source_ip)
            scan_type_counts[display_type] = (scan_type_counts[display_type] or 0) + 1
        end

        for scan_type, count in pairs(scan_type_counts) do
            report_text = report_text .. string.format("  %s: %d\n", scan_type, count)
        end
    end

    report_text = report_text .. "\n" .. string.rep("=", 93) .. "\n"
    report_text = report_text .. "End of Report\n"

    report_window:set(report_text)
end

-- Register menu item
register_menu("Scan Detector/Generate Report", generate_scan_report, MENU_TOOLS_UNSORTED)

-- Function to reset scan data
local function reset_scan_data()
    scan_data = {
        tcp_syn = {},
        tcp_connections = {},
        port_scans = {},
        arp_scans = {},
        udp_activity = {},
        timestamps = {},
        http_agents = {},
        scan_reports = {},
        dns_cache = {},
        nmap_indicators = {}
    }

    local info_window = TextWindow.new("Scan Detector")
    info_window:set("Scan detection data has been reset.\n")
end

register_menu("Scan Detector/Reset Data", reset_scan_data, MENU_TOOLS_UNSORTED)

-- Menu to show DNS cache
local function show_dns_cache()
    local dns_window = TextWindow.new("DNS Resolution Cache")

    local text = "=" .. string.rep("=", 60) .. "\n"
    text = text .. "  DNS RESOLUTION CACHE\n"
    text = text .. "=" .. string.rep("=", 60) .. "\n\n"
    text = text .. string.format("%-15s    %s\n", "IP Address", "Hostname")
    text = text .. string.rep("-", 60) .. "\n"

    local count = 0
    for ip, hostname in pairs(scan_data.dns_cache) do
        text = text .. string.format("%-15s -> %s\n", ip, hostname)
        count = count + 1
    end

    if count == 0 then
        text = text .. "(No DNS resolutions captured yet)\n"
    end

    text = text .. "\n" .. string.rep("-", 60) .. "\n"
    text = text .. string.format("Total entries: %d\n", count)

    dns_window:set(text)
end

register_menu("Scan Detector/Show DNS Cache", show_dns_cache, MENU_TOOLS_UNSORTED)

-- Create display filters for easy filtering
-- Usage: scandetector.source == "192.168.1.100"
--        scandetector.type == "SYN Scan"

print("========================================")
print("Scan Detector Plugin v0.1.0 Loaded")
print("========================================")
print("Available menu options:")
print("  - Tools > Scan Detector > Generate Report")
print("  - Tools > Scan Detector > Reset Data")
print("  - Tools > Scan Detector > Show DNS Cache")
print("")
print("Display filters:")
print("  - scandetector.source == <IP>")
print("  - scandetector.type == <scan type>")
print("  - scandetector.confidence == <HIGH|MEDIUM|LOW>")
print("========================================")
