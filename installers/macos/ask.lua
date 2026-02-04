--[[
    Analyst's Shark Knife (ASK) - Wireshark Lua Plugin Suite
    A comprehensive suite of plugins for security analytics and IOC research
    
    Features:
    - DNS Registration Info (RDAP)
    - ARIN IP Registration Data (RDAP) - IPv4 & IPv6
    - IP Reputation (AbuseIPDB, VirusTotal)
    - URL Categorization & Reputation (urlscan.io, VirusTotal, AlienVault OTX, URLhaus)
    - Domain Reputation (VirusTotal, AlienVault OTX)
    - IP Intelligence (Shodan, IPinfo, GreyNoise, AlienVault OTX, ThreatFox)
    - TLS/SSL Certificate Analysis (Direct certificate inspection + Certificate Transparency)
    - Email Analysis (SMTP/IMF)
    
    Version: 0.2.5
    Author: Walter Hofstetter
    License: GPL-2.0
--]]

-------------------------------------------------
-- Register plugin info with Wireshark
-------------------------------------------------

local ASK_BUILD = "2026-02-03 ssllabs-integration"

set_plugin_info({
    version = "0.2.5",
    author = "Walter Hofstetter",
    description = "Analyst's Shark Knife (ASK) - Comprehensive suite for security analytics and IOC research. Provides DNS registration info (RDAP), IP reputation (AbuseIPDB, VirusTotal), URL categorization (urlscan.io, VirusTotal, AlienVault OTX, URLhaus), IP intelligence (Shodan, IPinfo, GreyNoise, AlienVault OTX, ThreatFox), TLS certificate analysis, certificate transparency analysis, DNS analytics, and email analysis.",
    repository = "https://github.com/netwho/ask"
})

-------------------------------------------------
-- Utility Functions (must be defined before CONFIG)
-------------------------------------------------

local function log_message(message)
    print("[ASK] " .. message)
end

-- Read API key from file in home directory
local function read_api_key_from_file(service_name)
    -- Determine home directory based on platform
    local home_dir
    if package.config:sub(1,1) == "\\" then
        -- Windows
        home_dir = os.getenv("USERPROFILE")
    else
        -- Unix-like (macOS, Linux)
        home_dir = os.getenv("HOME")
    end
    
    if not home_dir then
        log_message("Cannot read API key file: HOME/USERPROFILE environment variable not set")
        return nil
    end
    
    -- Determine path separator
    local path_sep = package.config:sub(1,1) == "\\" and "\\" or "/"
    
    -- Try new directory first (.ask), then fall back to old directory (.ioc_researcher) for backward compatibility
    local config_dirs = {
        home_dir .. path_sep .. ".ask",
        home_dir .. path_sep .. ".ioc_researcher"  -- Backward compatibility
    }
    local key_file = nil
    
    for _, config_dir in ipairs(config_dirs) do
        local test_file = config_dir .. path_sep .. service_name .. "_API_KEY.txt"
        log_message("Checking for API key file: " .. test_file)
        local file = io.open(test_file, "r")
        if file then
            key_file = test_file
            file:close()
            break
        end
    end
    
    if not key_file then
        local dirs_msg = package.config:sub(1,1) == "\\" and 
                        "%USERPROFILE%\\.ask\\ or %USERPROFILE%\\.ioc_researcher\\" or
                        "~/.ask/ or ~/.ioc_researcher/"
        log_message("API key file not found in " .. dirs_msg)
        return nil
    end
    
    log_message("Reading API key from: " .. key_file)
    
    -- Try to read the file
    local file = io.open(key_file, "r")
    if file then
        -- Read entire file content
        local content = file:read("*all")
        file:close()
        
        if content and content ~= "" then
            -- Split by newlines and take first non-empty line
            local lines = {}
            for line in string.gmatch(content, "[^\r\n]+") do
                table.insert(lines, line)
            end
            
            -- Find first non-empty line
            local key = nil
            for _, line in ipairs(lines) do
                -- Trim whitespace from both ends (including newlines, spaces, tabs)
                local trimmed = string.gsub(line, "^%s+", "")
                trimmed = string.gsub(trimmed, "%s+$", "")
                -- Remove any remaining control characters
                trimmed = string.gsub(trimmed, "%c+", "")
                
                if trimmed ~= "" then
                    key = trimmed
                    break
                end
            end
            
            if key and key ~= "" then
                log_message("Successfully loaded API key for " .. service_name .. " from file (length: " .. string.len(key) .. " chars)")
                return key
            else
                log_message("API key file for " .. service_name .. " exists but contains no valid data")
            end
        else
            log_message("API key file for " .. service_name .. " exists but is empty")
        end
    else
        log_message("API key file not found: " .. key_file)
    end
    
    return nil
end

-- Get API key from environment variable, file, or fallback
local function get_api_key(service_name, env_var_name, fallback_value)
    -- Priority: 1. Environment variable, 2. File, 3. Fallback
    local key = os.getenv(env_var_name)
    if key and key ~= "" then
        return key
    end
    
    key = read_api_key_from_file(service_name)
    if key and key ~= "" then
        return key
    end
    
    return fallback_value or ""
end

-------------------------------------------------
-- Configuration
-------------------------------------------------

-- API Keys (set these in your environment or modify directly)
-- Get free API keys from:
--   AbuseIPDB: https://www.abuseipdb.com/api
--   urlscan.io: https://urlscan.io/user/signup
--   VirusTotal: https://www.virustotal.com/gui/join-us
--   Shodan: https://account.shodan.io/register

local CONFIG = {
    -- AbuseIPDB API Configuration
    -- Free tier: 1,000 requests/day
    -- API key priority: 1. Environment variable, 2. ~/.ask/ABUSEIPDB_API_KEY.txt, 3. Hardcoded fallback
    ABUSEIPDB_API_KEY = get_api_key("ABUSEIPDB", "ABUSEIPDB_API_KEY", "bc591215b84ecb07aa9d95ae0865ac1d12b5ecd4570ee5d96cc6ef54584bedccb0f99bfcf3410668"),
    ABUSEIPDB_ENABLED = true,
    
    -- urlscan.io API Configuration
    -- Free tier: 100 scans/day, 10,000 searches/day
    -- API key priority: 1. Environment variable, 2. ~/.ask/URLSCAN_API_KEY.txt
    URLSCAN_API_KEY = get_api_key("URLSCAN", "URLSCAN_API_KEY", ""),
    URLSCAN_ENABLED = true,
    
    -- VirusTotal API Configuration
    -- Free tier: 4 requests/minute, 500 requests/day
    -- API key priority: 1. Environment variable, 2. ~/.ask/VIRUSTOTAL_API_KEY.txt
    VIRUSTOTAL_API_KEY = get_api_key("VIRUSTOTAL", "VIRUSTOTAL_API_KEY", ""),
    VIRUSTOTAL_ENABLED = true,
    
    -- Shodan API Configuration
    -- NOTE: Host lookup endpoint requires paid membership ($49 one-time minimum)
    -- Free tier accounts cannot access IP host information
    -- API key priority: 1. Environment variable, 2. ~/.ask/SHODAN_API_KEY.txt
    SHODAN_API_KEY = get_api_key("SHODAN", "SHODAN_API_KEY", ""),
    SHODAN_ENABLED = true,
    
    -- IPinfo API Configuration
    -- Free tier: 50,000 requests/month (Lite API - country/ASN only)
    -- Paid tiers: Core/Plus/Business provide VPN/Proxy/Tor detection, hosting detection, abuse contacts
    -- API key priority: 1. Environment variable, 2. ~/.ask/IPINFO_API_KEY.txt
    IPINFO_API_KEY = get_api_key("IPINFO", "IPINFO_API_KEY", ""),
    IPINFO_ENABLED = true,
    
    -- GreyNoise API Configuration
    -- Community API: Free, no API key required
    -- Rate limit: 50 searches per week (combined with Visualizer)
    -- Identifies internet scanners vs legitimate services (RIOT dataset)
    GREYNOISE_ENABLED = true,
    GREYNOISE_API_URL = "https://api.greynoise.io/v3/community",
    
    -- AlienVault OTX API Configuration
    -- Free tier: Unlimited requests (community-driven threat intelligence)
    -- Registration: https://otx.alienvault.com (free account required)
    -- Provides IP, domain, URL, and file hash reputation with pulse data
    -- API key priority: 1. Environment variable, 2. ~/.ask/OTX_API_KEY.txt
    OTX_API_KEY = get_api_key("OTX", "OTX_API_KEY", ""),
    OTX_ENABLED = true,
    OTX_API_URL = "https://otx.alienvault.com/api/v1",
    
    -- Abuse.ch API Configuration (URLhaus + ThreatFox)
    -- Free tier: Fair use policy (free Auth-Key required)
    -- Registration: https://auth.abuse.ch (free Auth-Key)
    -- URLhaus: Malware URL detection, payload information, host lookups
    -- ThreatFox: IOC search (IP, domain, URL, hash), malware family identification
    -- API key priority: 1. Environment variable, 2. ~/.ask/ABUSECH_API_KEY.txt
    ABUSECH_API_KEY = get_api_key("ABUSECH", "ABUSECH_API_KEY", ""),
    ABUSECH_ENABLED = true,
    URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1",
    THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1",
    
    -- RDAP Configuration (no API key required)
    RDAP_ENABLED = true,
    RDAP_BOOTSTRAP_URL = "https://rdap.org",
    
    -- ARIN RDAP Configuration (supports IPv4 and IPv6)
    ARIN_RDAP_ENABLED = true,
    ARIN_RDAP_URL = "https://rdap.arin.net/registry",
    
    -- Certificate Transparency (crt.sh - no API key required)
    CERT_TRANSPARENCY_ENABLED = true,
    
    CRT_SH_URL = "https://crt.sh",
    
    -- Caching Configuration
    CACHE_ENABLED = true,
    CACHE_TTL_REPUTATION = 3600,  -- 1 hour for reputation data
    CACHE_TTL_REGISTRATION = 86400,  -- 24 hours for registration data
    
    -- Rate limiting awareness (requests per minute)
    RATE_LIMIT_DELAY = 0.1, -- seconds between requests
    MAX_RETRIES = 3,
    RETRY_DELAY = 1, -- seconds
}

-------------------------------------------------
-- Additional Utility Functions
-------------------------------------------------

-- Check if openssl is available
-- Uses cached result to avoid repeated shell commands
local openssl_check_cache = nil  -- nil = not checked, true/false = result

-- Forward declaration - execute_silent is defined later but we need it here
-- This will be set after execute_silent is defined
local execute_silent_early = nil

local function check_openssl_available()
    -- Return cached result if available
    if openssl_check_cache ~= nil then
        return openssl_check_cache
    end
    
    local is_windows = package.config:sub(1,1) == "\\"
    local result
    
    if is_windows then
        -- Windows: Use 'where' command to find openssl
        if execute_silent_early then
            -- Use silent execution to avoid cmd window flash
            result = execute_silent_early("where openssl")
        else
            -- Fallback during early init (before execute_silent is defined)
            local handle = io.popen("where openssl 2>nul")
            if handle then
                result = handle:read("*a")
                handle:close()
            end
        end
        if result and result ~= "" and not string.find(result, "Could not find") and not string.find(result, "INFO:") then
            openssl_check_cache = true
            return true, result
        end
    else
        -- Unix-like (macOS, Linux) - no window issues
        handle = io.popen("which openssl 2>&1")
        if handle then
            result = handle:read("*a")
            handle:close()
            if result and result ~= "" and not string.find(result, "not found") then
                openssl_check_cache = true
                return true, result
            end
        end
        
        -- Try direct execution test
        local test_handle = io.popen("openssl version 2>&1")
        if test_handle then
            local version_output = test_handle:read("*a")
            test_handle:close()
            if version_output and string.find(version_output, "OpenSSL") then
                openssl_check_cache = true
                return true, version_output
            end
        end
    end
    
    openssl_check_cache = false
    return false, nil
end

-- Check if curl is available
local function check_curl_available()
    local result
    local is_windows = package.config:sub(1,1) == "\\"
    
    if is_windows then
        -- Windows: Use 'where' to find curl.exe
        if execute_silent_early then
            -- Use silent execution to avoid cmd window flash
            result = execute_silent_early("where curl.exe")
        else
            -- Fallback during early init
            local handle = io.popen("where curl.exe 2>nul")
            if handle then
                result = handle:read("*a")
                handle:close()
            end
        end
        if result and result ~= "" and not string.find(result, "Could not find") and not string.find(result, "INFO:") then
            return true, result
        end
    else
        -- Unix-like: Use 'which' command (no window issues)
        handle = io.popen("which curl 2>&1")
        if handle then
            result = handle:read("*a")
            handle:close()
            if result and result ~= "" and not string.find(result, "not found") then
                return true, result
            end
        end
        
        -- Fallback: Try running curl directly to check version
        local test_handle = io.popen("curl --version 2>&1")
        if test_handle then
            local test_output = test_handle:read("*a")
            test_handle:close()
            if test_output and string.find(test_output, "curl") then
                return true, "curl (found via version check)"
            end
        end
    end
    
    return false, "curl not found in PATH"
end

-- Initialize curl availability variable
-- On Windows, defer the check to first use to avoid cmd window flash on plugin load
local curl_available = nil  -- nil means not checked yet
local curl_path = nil

-- Lazy curl check function
local function ensure_curl_checked()
    if curl_available == nil then
        curl_available, curl_path = check_curl_available()
        if not curl_available then
            log_message("WARNING: curl not found. HTTP requests will fail. Install curl first.")
        else
            log_message("curl found at: " .. string.gsub(curl_path or "", "\n", ""))
        end
    end
    return curl_available
end

-- On Unix, check immediately (no window flash issue)
-- On Windows, defer to first use
if package.config:sub(1,1) ~= "\\" then
    ensure_curl_checked()
end

-------------------------------------------------
-- Silent Command Execution (Windows)
-------------------------------------------------

-- Execute command silently on Windows (suppress command window)
-- This function uses VBScript to run commands without any visible window
local function execute_silent(cmd)
    local is_windows = package.config:sub(1,1) == "\\"
    
    if is_windows then
        -- On Windows, use a temp file approach to capture output silently
        -- VBScript with WScript.Shell.Run uses window style 0 (hidden)
        local temp_out = os.tmpname()
        local temp_bat = os.tmpname() .. ".bat"
        
        -- Create a batch file that runs the command and captures output
        local bat_file = io.open(temp_bat, "w")
        if bat_file then
            -- Write batch file that runs command silently
            bat_file:write("@echo off\r\n")
            bat_file:write(cmd .. " > \"" .. temp_out .. "\" 2>&1\r\n")
            bat_file:close()
            
            -- Create VBScript to run batch file hidden
            local temp_vbs = os.tmpname() .. ".vbs"
            local vbs_file = io.open(temp_vbs, "w")
            if vbs_file then
                -- WshShell.Run with 0 = hidden window, True = wait for completion
                vbs_file:write('Set WshShell = CreateObject("WScript.Shell")\n')
                vbs_file:write('WshShell.Run "cmd /c \"\"' .. temp_bat:gsub("\\", "\\\\") .. '\"\"", 0, True\n')
                vbs_file:close()
                
                -- Execute VBScript (this call itself may briefly flash, but much less than multiple commands)
                os.execute('cscript //nologo "' .. temp_vbs .. '"')
                
                -- Read output
                local output = ""
                local out_file = io.open(temp_out, "r")
                if out_file then
                    output = out_file:read("*a") or ""
                    out_file:close()
                end
                
                -- Cleanup
                os.remove(temp_vbs)
                os.remove(temp_bat)
                os.remove(temp_out)
                
                return output, true  -- Return output and success flag
            end
            os.remove(temp_bat)
        end
        
        -- Fallback: direct io.popen if VBScript approach fails
        local handle = io.popen(cmd .. " 2>&1")
        if handle then
            local result = handle:read("*a") or ""
            handle:close()
            return result, true
        end
        return "", false
    else
        -- On Unix-like systems, use io.popen normally (no window issues)
        local handle = io.popen(cmd .. " 2>&1")
        if handle then
            local result = handle:read("*a") or ""
            local success = handle:close()
            return result, success
        end
        return "", false
    end
end

-- Now that execute_silent is defined, make it available for tool checks
execute_silent_early = execute_silent

-------------------------------------------------
-- ASK Documents Directory and Logging
-------------------------------------------------

-- Global variable to store ASK documents directory
local ASK_DOCS_DIR = nil

-- Initialize ASK directory in Documents folder
local function init_ask_directory()
    -- Determine home directory based on platform
    local home_dir
    local path_sep
    local is_windows = package.config:sub(1,1) == "\\"
    
    if is_windows then
        -- Windows
        home_dir = os.getenv("USERPROFILE")
        path_sep = "\\"
    else
        -- Unix-like (macOS, Linux)
        home_dir = os.getenv("HOME")
        path_sep = "/"
    end
    
    if not home_dir then
        log_message("WARNING: Cannot determine home directory - logging disabled")
        return nil
    end
    
    -- Build path: Documents/ASK
    local docs_base = home_dir .. path_sep .. "Documents"
    local docs_dir = docs_base .. path_sep .. "ASK"
    
    -- First, try to write to the directory (it might already exist)
    local test_file = docs_dir .. path_sep .. ".ask_test"
    local f = io.open(test_file, "w")
    if f then
        f:close()
        os.remove(test_file)
        log_message("ASK directory initialized: " .. docs_dir)
        return docs_dir
    end
    
    -- Directory doesn't exist, try to create it
    -- On Windows, avoid os.execute/io.popen during init to prevent cmd window flash
    -- Use Lua's lfs if available, otherwise just try pure Lua approaches
    if is_windows then
        -- On Windows, we avoid shell commands during plugin load
        -- The directory will be created lazily when first log write is attempted
        -- For now, check if Documents exists and ASK can be created
        local docs_test = io.open(docs_base .. path_sep .. ".ask_test_docs", "w")
        if docs_test then
            docs_test:close()
            os.remove(docs_base .. path_sep .. ".ask_test_docs")
            -- Documents exists, but ASK subfolder doesn't
            -- We'll create it on first log write using PowerShell with -WindowStyle Hidden
            -- For now, just return the path and create lazily
            log_message("ASK directory path set (will create on first use): " .. docs_dir)
            return docs_dir
        end
        log_message("WARNING: Cannot access Documents folder - logging disabled")
        return nil
    else
        -- Unix-like: mkdir -p is safe and doesn't show any window
        local result = os.execute('mkdir -p "' .. docs_dir .. '" 2>/dev/null')
        
        -- Verify directory was created
        f = io.open(test_file, "w")
        if f then
            f:close()
            os.remove(test_file)
            log_message("ASK directory initialized: " .. docs_dir)
            return docs_dir
        end
    end
    
    log_message("WARNING: Cannot write to ASK directory - logging disabled")
    return nil
end

-- Get current date string for log filename (YYYY-MM-DD format)
local function get_date_string()
    return os.date("%Y-%m-%d")
end

-- Get current timestamp for log entries
local function get_timestamp()
    return os.date("%Y-%m-%d %H:%M:%S")
end

-- Ensure ASK directory exists (lazy creation for Windows)
local function ensure_ask_directory()
    if not ASK_DOCS_DIR then
        return false
    end
    
    local path_sep = package.config:sub(1,1) == "\\" and "\\" or "/"
    local test_file = ASK_DOCS_DIR .. path_sep .. ".ask_test"
    
    -- Check if directory exists by trying to write a test file
    local f = io.open(test_file, "w")
    if f then
        f:close()
        os.remove(test_file)
        return true
    end
    
    -- Directory doesn't exist, try to create it
    if package.config:sub(1,1) == "\\" then
        -- Windows: Use execute_silent to avoid cmd window flash
        local cmd = 'mkdir "' .. ASK_DOCS_DIR .. '"'
        execute_silent(cmd)
    else
        os.execute('mkdir -p "' .. ASK_DOCS_DIR .. '" 2>/dev/null')
    end
    
    -- Verify it was created
    f = io.open(test_file, "w")
    if f then
        f:close()
        os.remove(test_file)
        return true
    end
    
    return false
end

-- Append content to daily log file
local function append_to_log(query_type, query_target, result_content)
    if not ASK_DOCS_DIR then
        return false, "Logging not initialized"
    end
    
    -- Ensure directory exists (lazy creation)
    if not ensure_ask_directory() then
        return false, "Cannot create ASK directory: " .. ASK_DOCS_DIR
    end
    
    local path_sep = package.config:sub(1,1) == "\\" and "\\" or "/"
    local log_filename = "ASK-" .. get_date_string() .. ".log"
    local log_path = ASK_DOCS_DIR .. path_sep .. log_filename
    
    local f = io.open(log_path, "a")
    if not f then
        return false, "Cannot open log file: " .. log_path
    end
    
    -- Write log entry
    f:write(string.rep("=", 80) .. "\n")
    f:write("Timestamp: " .. get_timestamp() .. "\n")
    f:write("Query Type: " .. (query_type or "Unknown") .. "\n")
    f:write("Query Target: " .. (query_target or "Unknown") .. "\n")
    f:write(string.rep("-", 80) .. "\n")
    f:write(result_content .. "\n")
    f:write("\n")
    f:close()
    
    return true, log_path
end

-- Copy text to clipboard (platform-dependent)
local function copy_to_clipboard(text)
    if not text or text == "" then
        return false, "No text to copy"
    end
    
    local success = false
    local cmd
    
    if package.config:sub(1,1) == "\\" then
        -- Windows: Use clip command via execute_silent to avoid cmd window flash
        local temp_file = os.tmpname()
        local f = io.open(temp_file, "w")
        if f then
            f:write(text)
            f:close()
            cmd = 'type "' .. temp_file .. '" | clip'
            local result = execute_silent(cmd)
            os.remove(temp_file)
            -- execute_silent returns (output, success), check if it ran
            success = true  -- clip doesn't output anything, assume success if no error
        end
    else
        -- macOS: Use pbcopy
        if os.execute("which pbcopy >/dev/null 2>&1") == 0 or os.execute("which pbcopy >/dev/null 2>&1") == true then
            cmd = 'echo ' .. string.format('%q', text) .. ' | pbcopy'
            local result = os.execute(cmd)
            success = (result == 0 or result == true)
        -- Linux: Try xclip or xsel
        elseif os.execute("which xclip >/dev/null 2>&1") == 0 or os.execute("which xclip >/dev/null 2>&1") == true then
            cmd = 'echo ' .. string.format('%q', text) .. ' | xclip -selection clipboard'
            local result = os.execute(cmd)
            success = (result == 0 or result == true)
        elseif os.execute("which xsel >/dev/null 2>&1") == 0 or os.execute("which xsel >/dev/null 2>&1") == true then
            cmd = 'echo ' .. string.format('%q', text) .. ' | xsel --clipboard'
            local result = os.execute(cmd)
            success = (result == 0 or result == true)
        end
    end
    
    if success then
        return true, "Copied to clipboard"
    else
        return false, "Clipboard command not available"
    end
end

-- Initialize ASK directory on load
ASK_DOCS_DIR = init_ask_directory()

local function show_error_window(title, message)
    local win = TextWindow.new(title or "ASK Error")
    win:set(message)
end

local function show_result_window(title, content)
    local win = TextWindow.new(title or "ASK Results")
    win:set(content)
end

-- Enhanced result window with copy and log buttons
local function show_result_window_with_buttons(title, content, query_type, query_target)
    local win = TextWindow.new(title or "ASK Results")
    
    -- Set content directly without button text
    win:set(content)
    
    -- Add copy button
    win:add_button("Copy to Clipboard", function()
        local success, msg = copy_to_clipboard(content)
        if success then
            log_message("Copied to clipboard: " .. title)
        else
            log_message("Failed to copy to clipboard: " .. msg)
            show_error_window("Clipboard Error", "Failed to copy to clipboard:\n" .. msg)
        end
    end)
    
    -- Add log button
    win:add_button("Save to Log", function()
        local success, msg = append_to_log(query_type, query_target, content)
        if success then
            log_message("Saved to log: " .. msg)
            -- Show confirmation
            local confirm_win = TextWindow.new("Log Saved")
            confirm_win:set("Result saved to:\n" .. msg .. "\n\nQuery Type: " .. query_type .. "\nQuery Target: " .. query_target)
        else
            log_message("Failed to save to log: " .. msg)
            show_error_window("Log Error", "Failed to save to log:\n" .. msg)
        end
    end)
end

-- Extract field value from packet fields
local function get_field_value(fieldname, fieldtype, fields)
    fieldtype = fieldtype or "value"
    for i, field in ipairs(fields) do
        if field.name == fieldname then
            if fieldtype == "display" then
                return field.display
            elseif fieldtype == "value" then
                return field.value
            end
        end
    end
    return nil
end

-- Forward declarations for IP validation functions
local is_valid_ipv4, is_valid_ipv6, is_valid_ip, extract_ip_from_string

-- Validate IP address (IPv4)
is_valid_ipv4 = function(ip)
    if not ip or ip == "" then return false end
    local parts = {}
    for part in string.gmatch(ip, "(%d+)") do
        table.insert(parts, part)
    end
    if #parts ~= 4 then return false end
    for _, part in ipairs(parts) do
        local num = tonumber(part)
        if not num or num < 0 or num > 255 then
            return false
        end
    end
    return true
end

-- Validate IP address (IPv6) - basic validation
is_valid_ipv6 = function(ip)
    if not ip or ip == "" then return false end
    -- Basic IPv6 validation - check for colons and valid hex characters
    if string.find(ip, ":") == nil then return false end
    -- More comprehensive validation would check for proper IPv6 format
    -- For now, accept anything with colons that looks like IPv6
    return string.find(ip, "^%s*[%x:]+%s*$") ~= nil
end

-- Validate IP address (IPv4 or IPv6)
is_valid_ip = function(ip)
    return is_valid_ipv4(ip) or is_valid_ipv6(ip)
end

-- Check if an IPv4 address is RFC 1918 private address
local function is_rfc1918_private(ip)
    if not ip or not is_valid_ipv4(ip) then
        return false
    end
    
    -- Parse IP address into octets
    local parts = {}
    for part in string.gmatch(ip, "(%d+)") do
        table.insert(parts, tonumber(part))
    end
    
    if #parts ~= 4 then return false end
    
    local octet1, octet2 = parts[1], parts[2]
    
    -- RFC 1918 private address ranges:
    -- 10.0.0.0/8      (10.0.0.0 to 10.255.255.255)
    -- 172.16.0.0/12   (172.16.0.0 to 172.31.255.255)
    -- 192.168.0.0/16  (192.168.0.0 to 192.168.255.255)
    
    if octet1 == 10 then
        return true
    elseif octet1 == 172 and octet2 >= 16 and octet2 <= 31 then
        return true
    elseif octet1 == 192 and octet2 == 168 then
        return true
    end
    
    return false
end

-- Format RFC 1918 private address information
local function format_rfc1918_info(ip)
    local result = "=== RFC 1918 Private Address ===\n\n"
    result = result .. "IP Address: " .. ip .. "\n\n"
    result = result .. "This is a private (LAN) IP address as defined by RFC 1918.\n"
    result = result .. "Private addresses are not routable on the public Internet.\n\n"
    result = result .. "--- RFC 1918 Private Address Ranges ---\n"
    result = result .. "• 10.0.0.0/8       (10.0.0.0 to 10.255.255.255)\n"
    result = result .. "• 172.16.0.0/12   (172.16.0.0 to 172.31.255.255)\n"
    result = result .. "• 192.168.0.0/16  (192.168.0.0 to 192.168.255.255)\n\n"
    result = result .. "--- Why No External Information? ---\n"
    result = result .. "External threat intelligence services (Shodan, VirusTotal, AbuseIPDB, etc.)\n"
    result = result .. "cannot provide information about private addresses because:\n\n"
    result = result .. "• Private addresses are not publicly routable\n"
    result = result .. "• They exist only within local networks (LANs)\n"
    result = result .. "• Multiple networks can use the same private IP ranges\n"
    result = result .. "• External services cannot reach or scan these addresses\n\n"
    result = result .. "--- What You Can Do ---\n"
    result = result .. "• Check your local network documentation\n"
    result = result .. "• Review internal firewall logs\n"
    result = result .. "• Check local DNS records\n"
    result = result .. "• Use internal network scanning tools\n"
    result = result .. "• Review local network monitoring systems\n"
    
    return result
end

-- URL encode a string for use in query parameters
local function url_encode(str)
    if not str then return "" end
    -- Encode special characters
    str = string.gsub(str, "([^%w%-%.%_%~])", function(c)
        return string.format("%%%02X", string.byte(c))
    end)
    return str
end

-- Extract IP address from string that might contain hostname or other text
-- Handles formats like: "hostname (192.168.1.1)" or "192.168.1.1" or "hostname 192.168.1.1"
extract_ip_from_string = function(str)
    if not str or str == "" then return nil end
    
    -- First, try to find IP in parentheses: "hostname (192.168.1.1)" or "hostname (2001:db8::1)"
    local ip_in_parens = string.match(str, "%(([^%)]+)%)")
    if ip_in_parens then
        -- Check if it's a valid IPv4
        if is_valid_ipv4(ip_in_parens) then
            return ip_in_parens
        end
        -- Check if it's a valid IPv6
        if is_valid_ipv6(ip_in_parens) then
            return ip_in_parens
        end
    end
    
    -- Try to find IPv4 address pattern in the string (more specific pattern)
    -- Pattern: 1-3 digits, dot, 1-3 digits, dot, 1-3 digits, dot, 1-3 digits
    local ipv4_pattern = "(%d%d?%d?%.%d%d?%d?%.%d%d?%d?%.%d%d?%d?)"
    -- Try to match at word boundaries or start/end of string
    for ip in string.gmatch(str, ipv4_pattern) do
        if is_valid_ipv4(ip) then
            return ip
        end
    end
    
    -- Try to find IPv6 address pattern (more comprehensive)
    -- IPv6 can have various formats: 2001:db8::1, 2001:db8:0:0:0:0:0:1, etc.
    local ipv6_patterns = {
        "([%x:]+::[%x:]+)",  -- Compressed format with ::
        "([%x:]+:[%x:]+:[%x:]+:[%x:]+:[%x:]+:[%x:]+:[%x:]+:[%x:]+)",  -- Full format
    }
    for _, pattern in ipairs(ipv6_patterns) do
        local ipv6 = string.match(str, pattern)
        if ipv6 and is_valid_ipv6(ipv6) then
            return ipv6
        end
    end
    
    -- If the whole string is a valid IP, return it
    if is_valid_ip(str) then
        return str
    end
    
    return nil
end

-- Validate email address
local function is_valid_email(email)
    if not email or email == "" then return false end
    -- Extract email from angle brackets if present
    local clean_email = email
    local left_bracket = string.find(email, "<")
    if left_bracket then
        local right_bracket = string.find(email, ">", left_bracket)
        if right_bracket then
            clean_email = string.sub(email, left_bracket + 1, right_bracket - 1)
        end
    end
    -- Basic email validation
    return string.find(clean_email, "^%s*[%w%._%-]+@[%w%._%-]+%.[%w%._%-]+%s*$") ~= nil
end

-- Extract email address from field (handles "Name <email@domain.com>" format)
local function extract_email(email_field)
    if not email_field then return nil end
    local left_bracket = string.find(email_field, "<")
    if left_bracket then
        local right_bracket = string.find(email_field, ">", left_bracket)
        if right_bracket then
            return string.sub(email_field, left_bracket + 1, right_bracket - 1)
        end
    end
    return email_field
end

-- Validate domain name
local function is_valid_domain(domain)
    if not domain or domain == "" then return false end
    -- Basic domain validation
    return string.find(domain, "^%s*[%w%._-]+%.[%w%._-]+%s*$") ~= nil
end

-- Validate URL
local function is_valid_url(url)
    if not url or url == "" then return false end
    return string.find(url, "^https?://") ~= nil
end

-- HTTP POST request with error handling
local function http_post(url, headers, body)
    if not ensure_curl_checked() then
        return nil, "curl is not available. Please install curl to use this feature."
    end
    
    -- Build curl command
    local cmd = "curl -s -S --max-time 30"
    
    -- Add headers
    if headers then
        for key, value in pairs(headers) do
            cmd = cmd .. " -H '" .. key .. ": " .. value .. "'"
        end
    end
    
    -- Add POST data
    if body then
        cmd = cmd .. " -d '" .. string.gsub(body, "'", "'\\''") .. "'"
    end
    
    -- Add URL (must be last)
    cmd = cmd .. " '" .. string.gsub(url, "'", "'\\''") .. "'"
    
    log_message("Executing curl POST for: " .. url)
    
    local handle = io.popen(cmd)
    if not handle then
        return nil, "Failed to execute curl command"
    end
    
    local result = handle:read("*a")
    local exit_code
    local close_success, close_result = pcall(function() return handle:close() end)
    if close_success then
        exit_code = close_result
    end
    
    local is_success = false
    if exit_code == nil then
        is_success = (result and result ~= "")
    elseif exit_code == true or exit_code == 0 then
        is_success = true
    elseif exit_code == false then
        is_success = false
    else
        is_success = false
    end
    
    if result and result ~= "" then
        if string.find(result, "^curl:") or string.find(result, "curl: %d+") then
            return nil, "curl error: " .. string.sub(result, 1, 300)
        end
        
        if string.find(result, '"status":%s*[45]%d%d') or string.find(result, '"errorCode"') or string.find(result, '"error"') then
            local error_msg = string.match(result, '"message"%s*:%s*"([^"]*)"') or 
                             string.match(result, '"title"%s*:%s*"([^"]*)"') or
                             string.match(result, '"error"%s*:%s*"([^"]*)"') or
                             string.match(result, '"detail"%s*:%s*"([^"]*)"')
            
            if error_msg then
                if string.find(error_msg, "Expected") or string.find(error_msg, "parse") or string.find(error_msg, "JSON") then
                    return nil, "HTTP error: Malformed JSON response from server\n\n" ..
                              "Error details: " .. error_msg .. "\n\n" ..
                              "Response preview: " .. string.sub(result, 1, 300)
                end
                return nil, "HTTP error: " .. error_msg
            else
                return nil, "HTTP error: " .. string.sub(result, 1, 200)
            end
        end
        
        if is_success then
            return result, nil
        end
    end
    
    if not is_success then
        return nil, "HTTP request failed (exit code: " .. tostring(exit_code) .. ")"
    end
    
    return result, nil
end

local function http_get(url, headers, opts)
    headers = headers or {}
    opts = opts or {}
    
    if not url or url == "" then
        return nil, "Invalid URL: empty or nil"
    end
    
    -- Check if curl is available (lazy check on Windows to avoid cmd window flash)
    if not ensure_curl_checked() then
        return nil, "curl is not available. Please install curl first."
    end
    
    local is_windows = package.config:sub(1,1) == "\\"
    local result
    local is_success
    
    -- Build curl command
    -- Use -s (silent), -S (show errors), --max-time (timeout), -L (follow redirects)
    local cmd
    
    if is_windows then
        -- Windows: Build command with double-quote escaping
        cmd = 'curl -s -S --max-time 30 -L'
        
        -- Add headers
        for key, value in pairs(headers) do
            cmd = cmd .. ' -H "' .. key .. ': ' .. value .. '"'
        end
        
        -- Add URL with double quotes
        cmd = cmd .. ' "' .. url .. '"'
        
        log_message("Executing curl (silent) for: " .. url)
        
        -- Use execute_silent to avoid cmd window flash
        result, is_success = execute_silent(cmd)
        
        -- execute_silent returns (output, success_flag)
        -- Treat any non-empty result as potential success
        if result and result ~= "" then
            is_success = true
        end
    else
        -- Unix: Build command with single-quote escaping
        local cmd_parts = {"curl", "-s", "-S", "--max-time", "30", "-L"}
        
        -- Add headers
        for key, value in pairs(headers) do
            table.insert(cmd_parts, "-H")
            table.insert(cmd_parts, key .. ": " .. value)
        end
        
        -- Add URL
        table.insert(cmd_parts, url)
        
        -- Convert to command string with proper quoting
        cmd = ""
        for i, part in ipairs(cmd_parts) do
            if i > 1 then cmd = cmd .. " " end
            -- Quote arguments that contain spaces or special characters
            if string.find(part, "[ %$`\"'\\]") then
                -- Escape single quotes and wrap in single quotes
                local escaped = string.gsub(part, "'", "'\\''")
                cmd = cmd .. "'" .. escaped .. "'"
            else
                cmd = cmd .. part
            end
        end
        
        log_message("Executing curl for: " .. url)
        
        local handle = io.popen(cmd)
        if not handle then
            return nil, "Failed to execute curl command. Command: " .. cmd
        end
        
        result = handle:read("*a")
        
        -- Try to get exit code, but handle nil gracefully (common on macOS)
        local exit_code
        local close_success, close_result = pcall(function() return handle:close() end)
        if close_success then
            exit_code = close_result
        end
        
        -- Determine if the request was successful
        -- exit_code can be: 0 (success), non-zero (failure), true (success), false (failure), or nil
        is_success = false
        if exit_code == nil then
            -- No exit code available, check result content
            is_success = (result and result ~= "")
        elseif exit_code == true or exit_code == 0 then
            -- Boolean true or numeric 0 means success
            is_success = true
        elseif exit_code == false then
            -- Boolean false means failure
            is_success = false
        else
            -- Numeric non-zero means failure
            is_success = false
        end
    end
    
    -- If we have a result, check if it looks like an error
    if result and result ~= "" then
        -- Check for curl error messages
        if string.find(result, "^curl:") or string.find(result, "curl: %d+") then
            return nil, "curl error: " .. string.sub(result, 1, 300)
        end
        
        -- If caller allows JSON errors, return JSON payload as-is
        if opts.allow_error_json and string.match(result, "^%s*%{") then
            return result, nil
        end

        -- Check for HTTP error responses in JSON (4xx, 5xx)
        local prefix = string.sub(result, 1, 200)
        local is_json_error = prefix:match('^%s*%{[%s\r\n]*"error"%s*:') or
                             prefix:match('^%s*%{[%s\r\n]*"errorCode"%s*:') or
                             prefix:match('^%s*%{[%s\r\n]*"status"%s*:%s*[45]%d%d')
        if not opts.allow_error_json and is_json_error then
            -- Try to extract error message from JSON (handle escaped quotes)
            -- Pattern: "message": "text" or "message": "text with \"escaped\" quotes"
            local error_msg = string.match(result, '"message"%s*:%s*"([^"]*)"') or 
                             string.match(result, '"title"%s*:%s*"([^"]*)"') or
                             string.match(result, '"error"%s*:%s*"([^"]*)"') or
                             string.match(result, '"detail"%s*:%s*"([^"]*)"')
            
            -- If no simple match, try to get text after the key (handles escaped quotes)
            if not error_msg then
                -- Look for "message": "..." pattern, handling escaped quotes
                local msg_start = string.find(result, '"message"%s*:%s*"')
                if msg_start then
                    -- Find the closing quote, skipping escaped quotes
                    local pos = msg_start + 11 -- After "message": "
                    local msg_end = pos
                    while msg_end <= string.len(result) do
                        local char = string.sub(result, msg_end, msg_end)
                        if char == '"' and string.sub(result, msg_end - 1, msg_end - 1) ~= "\\" then
                            break
                        end
                        msg_end = msg_end + 1
                    end
                    if msg_end > pos then
                        error_msg = string.sub(result, pos, msg_end - 1)
                        -- Unescape common sequences
                        error_msg = string.gsub(error_msg, '\\"', '"')
                        error_msg = string.gsub(error_msg, '\\\\', '\\')
                    end
                end
            end
            
            if error_msg then
                -- Check if error message looks like a JSON parsing error
                if string.find(error_msg, "Expected") or string.find(error_msg, "parse") or string.find(error_msg, "JSON") then
                    return nil, "HTTP error: Malformed JSON response from server\n\n" ..
                              "Error details: " .. error_msg .. "\n\n" ..
                              "This might indicate:\n" ..
                              "- Server returned invalid JSON\n" ..
                              "- Response contains unescaped special characters\n" ..
                              "- Network/proxy corruption\n\n" ..
                              "Response preview: " .. string.sub(result, 1, 300)
                end
                return nil, "HTTP error: " .. error_msg
            else
                -- If we can't parse the error, return a generic message with response preview
                return nil, "HTTP error: " .. string.sub(result, 1, 200)
            end
        end
        
        -- If we have a valid result and exit code indicates success (or is nil), return it
        if is_success then
            return result, nil
        end
    end
    
    -- If exit code indicates failure
    if not is_success then
        if not result or result == "" then
            return nil, "HTTP request failed (exit code: " .. tostring(exit_code) .. ").\nURL: " .. url .. "\n\nTroubleshooting:\n- Check internet connectivity\n- Verify the URL is accessible\n- Check firewall/proxy settings"
        else
            -- Even with a result, if exit code says failure, it might be an error response
            -- But if it looks like valid JSON/data, return it anyway (some APIs return data with non-zero codes)
            if string.find(result, "^%s*{") or string.find(result, "^%s*%[") then
                -- Looks like JSON, might be valid despite exit code
                return result, nil
            end
            return nil, "HTTP request failed (exit code: " .. tostring(exit_code) .. ").\nResponse: " .. string.sub(result, 1, 300)
        end
    end
    
    -- If no result and exit code indicates success, might still be an error
    if (not result or result == "") then
        if exit_code == nil then
            -- On some systems, exit_code can be nil even on success
            return nil, "HTTP request returned empty response.\nURL: " .. url .. "\n\nThis might indicate:\n- Network connectivity issues\n- The API endpoint is down\n- Rate limiting or access restrictions"
        end
        return nil, "HTTP request returned empty response. URL: " .. url
    end
    
    return result, nil
end

-- Check for JSON library availability at startup
local json_library_available = false
do
    local json_available, json = pcall(require, "json")
    if json_available and json and json.decode then
        json_library_available = true
        log_message("JSON library (json.lua) detected and available - will use for all JSON parsing")
    else
        log_message("JSON library not found - using simple parser (install json.lua for better parsing)")
        log_message("  Install: curl -o ~/.local/lib/wireshark/plugins/json.lua https://raw.githubusercontent.com/rxi/json.lua/master/json.lua")
    end
end

-- Parse JSON (simple parser for basic JSON structures)
local function parse_json(json_str)
    if not json_str or json_str == "" then
        return nil
    end
    
    -- Try to use Lua's JSON library if available, otherwise use simple parsing
    if json_library_available then
        local json = require("json")
        local success, result, err = pcall(function()
            return json.decode(json_str)
        end)
        if success and result then
            return result
        elseif not success and err then
            -- JSON library failed to parse - log the error for debugging
            log_message("JSON library parse error: " .. tostring(err))
            -- Fall through to simple parser
        end
    end
    
    -- Fallback: Enhanced simple JSON parser for RDAP and API responses
    local result = {}
    
    -- Try to parse as object { ... }
    if string.sub(json_str, 1, 1) == "{" then
        -- Extract simple string key-value pairs (most common)
        for key, value in string.gmatch(json_str, '"([^"]+)":%s*"([^"]+)"') do
            result[key] = value
        end
        
        -- Extract numeric values (integers and floats)
        for key, value in string.gmatch(json_str, '"([^"]+)":%s*([%d%.%-]+)') do
            local num = tonumber(value)
            if num then
                result[key] = num
            end
        end
        
        -- Extract boolean values
        for key, value in string.gmatch(json_str, '"([^"]+)":%s*(true|false)') do
            result[key] = (value == "true")
        end
        
        -- Extract null values
        for key in string.gmatch(json_str, '"([^"]+)":%s*null') do
            result[key] = nil
        end
        
        -- Extract arrays (including nested objects)
        -- Pattern: "key": [ ... ] where content can be strings, numbers, objects, etc.
        for key, array_content in string.gmatch(json_str, '"([^"]+)":%s*%[([^%]]*)%]') do
            local items = {}
            -- Extract quoted strings from array
            for item in string.gmatch(array_content, '"([^"]+)"') do
                table.insert(items, item)
            end
            -- Extract numbers from array
            for item in string.gmatch(array_content, "([%d%.%-]+)") do
                local num = tonumber(item)
                if num and not string.find(array_content, '"' .. item .. '"') then
                    -- Only add if it's not part of a string
                    table.insert(items, num)
                end
            end
            -- Extract objects from array (simplified - just mark as object)
            -- For complex arrays with objects, we'll need the full JSON library
            if #items > 0 then
                result[key] = items
            else
                -- Empty array or array with objects - create empty array to preserve structure
                result[key] = {}
            end
        end
        
        -- Try to extract arrays with nested objects more carefully
        -- Look for "results": [{...}, {...}] pattern
        local results_match = string.match(json_str, '"results"%s*:%s*%[%s*({.+})%s*%]')
        if results_match then
            -- This is a complex array - we'll need to parse it differently
            -- For now, mark that results exists
            if not result.results then
                result.results = {}
            end
        end
        
        -- Extract nested objects (like entities, events, links)
        -- This is a simplified extraction - we'll get the outer structure
        for key in string.gmatch(json_str, '"([^"]+)":%s*%[') do
            if not result[key] then
                result[key] = {}
            end
        end
        
        -- Extract events array with eventAction and eventDate
        -- Pattern: "eventAction": "registration", "eventDate": "2017-02-24T13:34:51Z"
        for event_action, event_date in string.gmatch(json_str, '"eventAction"%s*:%s*"([^"]+)"[^}]*"eventDate"%s*:%s*"([^"]+)"') do
            if not result.events then result.events = {} end
            table.insert(result.events, {eventAction = event_action, eventDate = event_date})
        end
        
        -- Extract entities array (simplified - we'll get basic structure)
        -- Look for entities with abuse role
        local entities_start = string.find(json_str, '"entities"%s*:%s*%[')
        if entities_start then
            result.entities = {}
            -- Try to extract abuse contact email directly from JSON string
            local abuse_email = string.match(json_str, '"roles"%s*:%s*%[%s*"abuse"[^}]*"email"%s*:%s*"([^"]+)"')
            if abuse_email then
                table.insert(result.entities, {
                    roles = {"abuse"},
                    vcardArray = {{}, {{"email", {}, abuse_email}}}
                })
            end
        end
        
        -- Extract specific important fields that might be nested
        -- startAddress and endAddress (critical for IP ranges)
        local start_addr = string.match(json_str, '"startAddress"%s*:%s*"([^"]+)"')
        local end_addr = string.match(json_str, '"endAddress"%s*:%s*"([^"]+)"')
        if start_addr then result.startAddress = start_addr end
        if end_addr then result.endAddress = end_addr end
        
        -- Extract CIDR notation (APNIC and other RIRs use this)
        local cidr = string.match(json_str, '"v4prefix"%s*:%s*"([^"]+)"') or string.match(json_str, '"v6prefix"%s*:%s*"([^"]+)"')
        if cidr then
            result.cidr = cidr
            if not result.cidr0_cidrs then result.cidr0_cidrs = {} end
            if not result.cidr0_cidrs[1] then result.cidr0_cidrs[1] = {} end
            result.cidr0_cidrs[1].v4prefix = string.match(cidr, "^%d+%.%d+%.%d+%.%d+/%d+$") and cidr or nil
            result.cidr0_cidrs[1].v6prefix = string.match(cidr, ":") and cidr or nil
        end
        
        -- Extract abuse contact emails from entities
        -- Look for entities with "abuse" role and extract email addresses
        for abuse_email in string.gmatch(json_str, '"roles"%s*:%s*%[%s*"abuse"[^}]*"email"%s*:%s*"([^"]+)"') do
            if not result.abuse_emails then result.abuse_emails = {} end
            table.insert(result.abuse_emails, abuse_email)
        end
        
        -- Extract name, handle, type (common across all RIRs)
        local name = string.match(json_str, '"name"%s*:%s*"([^"]+)"')
        local handle = string.match(json_str, '"handle"%s*:%s*"([^"]+)"')
        local net_type = string.match(json_str, '"netType"%s*:%s*"([^"]+)"')
        if name then result.name = name end
        if handle then result.handle = handle end
        if net_type then result.netType = net_type end
        
        -- Extract parentHandle
        local parent = string.match(json_str, '"parentHandle"%s*:%s*"([^"]+)"')
        if parent then result.parentHandle = parent end
        
        -- Extract objectClassName
        local obj_class = string.match(json_str, '"objectClassName"%s*:%s*"([^"]+)"')
        if obj_class then result.objectClassName = obj_class end
        
        -- Extract country code (APNIC and other RIRs include this)
        local country = string.match(json_str, '"country"%s*:%s*"([^"]+)"')
        if country then result.country = country end
        
        -- If we extracted any data, return it
        if next(result) ~= nil then
            return result
        end
    end
    
    -- If all parsing fails, return raw string wrapped in a table
    -- This allows the formatting functions to still work
    return {raw = json_str, _parse_error = true}
end

-- Format JSON for display
local function format_json(data, indent)
    indent = indent or 0
    local indent_str = string.rep("  ", indent)
    
    if type(data) == "table" then
        local result = "{\n"
        for key, value in pairs(data) do
            result = result .. indent_str .. "  " .. tostring(key) .. ": "
            if type(value) == "table" then
                result = result .. format_json(value, indent + 1)
            else
                result = result .. tostring(value)
            end
            result = result .. "\n"
        end
        result = result .. indent_str .. "}"
        return result
    else
        return tostring(data)
    end
end

-------------------------------------------------
-- Simple Cache Implementation
-------------------------------------------------

local cache = {}

local function cache_key(service, ioc)
    if not service then service = "unknown" end
    if not ioc then ioc = "unknown" end
    return tostring(service) .. ":" .. tostring(ioc)
end

local function cache_get(service, ioc)
    if not CONFIG.CACHE_ENABLED then return nil end
    
    if not service then service = "unknown" end
    if not ioc then ioc = "unknown" end
    local key = cache_key(service, ioc)
    
    local cached = cache[key]
    
    if cached then
        local ttl = CONFIG.CACHE_TTL_REPUTATION
        if service == "rdap" or service == "arin" then
            ttl = CONFIG.CACHE_TTL_REGISTRATION
        end
        
        if os.time() - cached.timestamp < ttl then
            return cached.data
        else
            cache[key] = nil -- Expired
        end
    end
    
    return nil
end

local function cache_set(service, ioc, data)
    if not CONFIG.CACHE_ENABLED then return end
    
    if not service then service = "unknown" end
    if not ioc then ioc = "unknown" end
    local key = cache_key(service, ioc)
    
    cache[key] = {
        data = data,
        timestamp = os.time()
    }
end

-------------------------------------------------
-- DNS Registration Info Module (RDAP)
-------------------------------------------------

-- Extract base domain from subdomain (e.g., www.example.com -> example.com)
local function get_base_domain(domain)
    if not domain then return nil end
    
    -- Remove common subdomain prefixes
    local base = domain
    -- Remove www., mail., ftp., etc. prefixes
    base = string.gsub(base, "^[%w%-]+%.", "", 1)
    
    -- Count dots to determine if it's a subdomain
    local dot_count = 0
    for _ in string.gmatch(base, "%.") do
        dot_count = dot_count + 1
    end
    
    -- If more than one dot, might be a subdomain (e.g., sub.example.com)
    -- For RDAP, we typically want the base domain (last two parts)
    -- But keep the original if it's already a base domain
    if dot_count > 1 then
        -- Extract last two parts (e.g., example.com from sub.example.com)
        local parts = {}
        for part in string.gmatch(base, "([^%.]+)") do
            table.insert(parts, part)
        end
        if #parts >= 2 then
            base = parts[#parts - 1] .. "." .. parts[#parts]
        end
    end
    
    return base
end

local function lookup_domain_rdap(domain)
    if not is_valid_domain(domain) then
        return nil, "Invalid domain name"
    end
    
    -- Try with the original domain first
    local base_domain = get_base_domain(domain)
    local domains_to_try = {}
    
    -- Add original domain if different from base
    if domain ~= base_domain then
        table.insert(domains_to_try, domain)
    end
    -- Always try base domain
    table.insert(domains_to_try, base_domain)
    
    local last_err = nil
    
    for _, test_domain in ipairs(domains_to_try) do
        -- URL encode the domain
        local domain_encoded = url_encode(test_domain)
        local url = CONFIG.RDAP_BOOTSTRAP_URL .. "/domain/" .. domain_encoded
        
        log_message("Querying RDAP for domain: " .. test_domain .. " (URL: " .. url .. ")")
        
        local response, err = http_get(url)
        if err then
            -- Check if error is about empty response (domain not found in RDAP)
            -- Match various forms: "empty response", "Empty response", "HTTP request returned empty"
            if string.find(string.lower(err), "empty response") or string.find(err, "HTTP request returned empty") then
                -- Empty response from RDAP means domain not found - this is normal
                last_err = "Domain not found in RDAP registry: " .. test_domain .. "\n\n" ..
                          "RDAP returned an empty response, which typically means:\n" ..
                          "• Domain is not registered in an RDAP-compatible registry\n" ..
                          "• Domain uses a TLD that doesn't support RDAP\n" ..
                          "• Domain registration is private or not publicly available\n\n" ..
                          "RDAP domain lookups work best for major TLDs (.com, .org, .net, .io, etc.)\n" ..
                          "registered through RDAP-compatible registrars.\n\n" ..
                          "Alternative: Use Certificate Transparency or DNS tools for domain analysis."
            elseif string.find(err, "404") or string.find(err, "not found") or string.find(err, "No known RDAP") then
                last_err = "Domain not found in RDAP registry: " .. test_domain .. "\n\n" ..
                          "This domain may not be registered in an RDAP-compatible registry.\n" ..
                          "RDAP domain lookups are only available for domains registered through\n" ..
                          "registries that support RDAP (most major TLDs like .com, .org, .net).\n" ..
                          "Some newer TLDs or country-code domains may not be available."
            else
                last_err = err
            end
            -- Try next domain if we have more to try
            if test_domain ~= domains_to_try[#domains_to_try] then
                log_message("RDAP lookup failed for " .. test_domain .. ", trying base domain...")
            end
        elseif not response or response == "" then
            -- Empty response means domain not found in RDAP (404 equivalent)
            -- This is normal for domains not in RDAP registries
            last_err = "Domain not found in RDAP registry: " .. test_domain .. "\n\n" ..
                      "RDAP returned an empty response, which typically means:\n" ..
                      "• Domain is not registered in an RDAP-compatible registry\n" ..
                      "• Domain uses a TLD that doesn't support RDAP\n" ..
                      "• Domain registration is private or not publicly available\n\n" ..
                      "RDAP domain lookups work best for major TLDs (.com, .org, .net, .io, etc.)\n" ..
                      "registered through RDAP-compatible registrars.\n\n" ..
                      "Alternative: Use Certificate Transparency or DNS tools for domain analysis."
            -- Try next domain if we have more to try
            if test_domain ~= domains_to_try[#domains_to_try] then
                log_message("RDAP returned empty response for " .. test_domain .. ", trying base domain...")
            end
        else
            local data = parse_json(response)
            if not data then
                last_err = "Failed to parse RDAP response for domain: " .. test_domain
                if test_domain ~= domains_to_try[#domains_to_try] then
                    log_message("Failed to parse RDAP response for " .. test_domain .. ", trying base domain...")
                end
            elseif data.ldhName or data.handle or data.entities then
                -- Check if we got valid data
                log_message("Successfully retrieved RDAP data for domain: " .. test_domain)
                return data, nil
            else
                -- Check for error in response
                if data.errorCode or data.title then
                    local error_msg = data.title or tostring(data.errorCode)
                    last_err = "RDAP error for domain " .. test_domain .. ": " .. error_msg
                else
                    last_err = "RDAP returned invalid data for domain: " .. test_domain
                end
            end
        end
    end
    
    -- If we get here, all attempts failed
    return nil, last_err or ("RDAP lookup failed for domain: " .. domain .. "\n\n" ..
                             "RDAP domain lookups are only available for domains registered through\n" ..
                             "RDAP-compatible registries (most major TLDs like .com, .org, .net, .io).\n\n" ..
                             "Possible reasons:\n" ..
                             "• Domain not registered in an RDAP-compatible registry\n" ..
                             "• Domain uses a TLD that doesn't support RDAP\n" ..
                             "• Domain registration is too new or private\n" ..
                             "• Rate limiting or temporary service unavailability\n\n" ..
                             "Alternative: Use Certificate Transparency or DNS Registration Info\n" ..
                             "for domain analysis, or try WHOIS tools.")
end

local function format_rdap_domain_result(data)
    if not data then return "No data available" end
    
    local result = "=== DNS Registration Info (RDAP) ===\n\n"
    
    if data.ldhName then
        result = result .. "Domain: " .. data.ldhName .. "\n"
    end
    
    if data.handle then
        result = result .. "Handle: " .. data.handle .. "\n"
    end
    
    if data.status then
        result = result .. "Status: " .. table.concat(data.status, ", ") .. "\n"
    end
    
    if data.entities then
        result = result .. "\n--- Entities ---\n"
        for i, entity in ipairs(data.entities) do
            if entity.roles then
                result = result .. "\nRole: " .. table.concat(entity.roles, ", ") .. "\n"
            end
            if entity.vcardArray then
                -- Extract name and organization from vCard
                local vcard = entity.vcardArray[2]
                if vcard then
                    for j, item in ipairs(vcard) do
                        if item[1] == "fn" then
                            result = result .. "Name: " .. item[3] .. "\n"
                        elseif item[1] == "org" then
                            result = result .. "Organization: " .. item[3] .. "\n"
                        elseif item[1] == "email" then
                            result = result .. "Email: " .. item[3] .. "\n"
                        end
                    end
                end
            end
        end
    end
    
    if data.nameservers then
        result = result .. "\n--- Name Servers ---\n"
        -- Check if nameservers is an array
        if type(data.nameservers) == "table" then
            for i, ns in ipairs(data.nameservers) do
                if type(ns) == "table" then
                    -- Nameserver is an object with ldhName property
                    if ns.ldhName then
                        result = result .. ns.ldhName .. "\n"
                    elseif ns.name then
                        result = result .. ns.name .. "\n"
                    end
                elseif type(ns) == "string" then
                    -- Nameserver is a simple string
                    result = result .. ns .. "\n"
                elseif type(ns) == "number" then
                    -- Unexpected: nameserver as number (skip or convert)
                    log_message("Warning: nameserver at index " .. i .. " is a number: " .. tostring(ns))
                    -- Skip numbers
                else
                    -- Unknown type, try to convert to string
                    log_message("Warning: nameserver at index " .. i .. " has unexpected type: " .. type(ns))
                    result = result .. tostring(ns) .. "\n"
                end
            end
        else
            -- nameservers is not an array, might be a single value
            result = result .. tostring(data.nameservers) .. "\n"
        end
    end
    
    -- Extract registration date and calculate domain age
    local registration_date = nil
    local last_changed_date = nil
    local domain_age_days = nil
    
    if data.events then
        result = result .. "\n--- Registration Events ---\n"
        -- Check if events is an array
        if type(data.events) == "table" then
            for i, event in ipairs(data.events) do
                if type(event) == "table" then
                    -- Event is an object with eventAction and eventDate properties
                    if event.eventAction and event.eventDate then
                        local action = string.lower(tostring(event.eventAction))
                        local date_str = tostring(event.eventDate)
                        
                        result = result .. event.eventAction .. ": " .. date_str .. "\n"
                        
                        -- Extract registration date
                        if string.find(action, "registration") or string.find(action, "registered") then
                            registration_date = date_str
                        elseif string.find(action, "last changed") or string.find(action, "last changed") then
                            last_changed_date = date_str
                        end
                    elseif event.eventAction then
                        result = result .. event.eventAction .. "\n"
                    end
                elseif type(event) == "string" then
                    -- Event is a simple string
                    result = result .. event .. "\n"
                elseif type(event) == "number" then
                    -- Unexpected: event as number (skip)
                    log_message("Warning: event at index " .. i .. " is a number: " .. tostring(event))
                else
                    -- Unknown type, try to convert to string
                    log_message("Warning: event at index " .. i .. " has unexpected type: " .. type(event))
                    result = result .. tostring(event) .. "\n"
                end
            end
        else
            -- events is not an array, might be a single value
            result = result .. tostring(data.events) .. "\n"
        end
    end
    
    -- Calculate domain age if we have registration date
    if registration_date then
        -- Parse ISO 8601 date (e.g., "2017-02-24T13:34:51Z" or "2017-02-24")
        local year, month, day = string.match(registration_date, "(%d%d%d%d)%-(%d%d)%-(%d%d)")
        if year and month and day then
            local reg_time = os.time({
                year = tonumber(year),
                month = tonumber(month),
                day = tonumber(day),
                hour = 0,
                min = 0,
                sec = 0
            })
            local current_time = os.time()
            domain_age_days = math.floor((current_time - reg_time) / 86400) -- seconds to days
            
            result = result .. "\n--- Domain Age Analysis ---\n"
            result = result .. "Registration Date: " .. registration_date .. "\n"
            
            if domain_age_days >= 0 then
                if domain_age_days < 30 then
                    result = result .. "⚠ Domain Age: " .. domain_age_days .. " days (FRESHLY REGISTERED)\n"
                    result = result .. "\n⚠ SECURITY WARNING: This domain was registered very recently.\n"
                    result = result .. "Freshly registered domains are commonly used for:\n"
                    result = result .. "• Phishing campaigns\n"
                    result = result .. "• Malware distribution\n"
                    result = result .. "• Spam operations\n"
                    result = result .. "• Fraudulent activities\n"
                    result = result .. "• Temporary C2 infrastructure\n\n"
                    result = result .. "Recommendations:\n"
                    result = result .. "• Exercise extra caution with this domain\n"
                    result = result .. "• Check domain reputation (VirusTotal, urlscan.io)\n"
                    result = result .. "• Review certificate transparency logs\n"
                    result = result .. "• Monitor for suspicious activity\n"
                elseif domain_age_days < 90 then
                    result = result .. "⚠ Domain Age: " .. domain_age_days .. " days (RECENTLY REGISTERED)\n"
                    result = result .. "\n⚠ Note: This domain was registered recently (less than 3 months ago).\n"
                    result = result .. "While not necessarily suspicious, recently registered domains\n"
                    result = result .. "should be evaluated with additional scrutiny.\n"
                elseif domain_age_days < 365 then
                    result = result .. "Domain Age: " .. domain_age_days .. " days (less than 1 year old)\n"
                else
                    local years = math.floor(domain_age_days / 365)
                    local remaining_days = domain_age_days % 365
                    result = result .. "Domain Age: " .. years .. " year" .. (years > 1 and "s" or "") .. 
                            (remaining_days > 0 and (", " .. remaining_days .. " days") or "") .. " (established)\n"
                end
            end
        end
    end
    
    if last_changed_date and last_changed_date ~= registration_date then
        result = result .. "Last Changed: " .. last_changed_date .. "\n"
    end
    
    return result
end

local function dns_rdap_callback(...)
    local fields = {...}
    local domain = get_field_value("dns.qry.name", "value", fields)
    
    if not domain then
        show_error_window("DNS RDAP Lookup", "Could not extract domain name from packet")
        return
    end
    
    local data, err = lookup_domain_rdap(domain)
    if err then
        show_error_window("DNS RDAP Lookup Error", "Error querying RDAP:\n" .. err)
        return
    end
    
    local formatted = format_rdap_domain_result(data)
    show_result_window_with_buttons("DNS Registration Info: " .. domain, formatted, "DNS RDAP", domain)
end

-------------------------------------------------
-- ARIN IP Registration Module (RDAP)
-------------------------------------------------

-- Detect which RIR (Regional Internet Registry) provided the response
local function detect_rir(data, response)
    if not data and not response then return "Unknown" end
    
    local response_str = response or ""
    if data then
        -- Check rdapConformance for RIR-specific profiles
        if data.rdapConformance then
            local conformance = type(data.rdapConformance) == "table" and table.concat(data.rdapConformance, " ") or tostring(data.rdapConformance)
            if string.find(conformance, "arin") then
                return "ARIN (North America)"
            elseif string.find(conformance, "ripe") then
                return "RIPE NCC (Europe, Middle East, Central Asia)"
            elseif string.find(conformance, "apnic") then
                return "APNIC (Asia-Pacific)"
            elseif string.find(conformance, "lacnic") then
                return "LACNIC (Latin America & Caribbean)"
            elseif string.find(conformance, "afrinic") then
                return "AFRINIC (Africa)"
            end
        end
        
        -- Check links for RIR-specific URLs
        if data.links then
            for _, link in ipairs(data.links) do
                if link.href then
                    if string.find(link.href, "rdap%.arin%.net") then
                        return "ARIN (North America)"
                    elseif string.find(link.href, "rdap%.ripe%.net") or string.find(link.href, "rdap%.db%.ripe%.net") then
                        return "RIPE NCC (Europe, Middle East, Central Asia)"
                    elseif string.find(link.href, "rdap%.apnic%.net") then
                        return "APNIC (Asia-Pacific)"
                    elseif string.find(link.href, "rdap%.lacnic%.net") then
                        return "LACNIC (Latin America & Caribbean)"
                    elseif string.find(link.href, "rdap%.afrinic%.net") then
                        return "AFRINIC (Africa)"
                    end
                end
            end
        end
    end
    
    -- Check raw response for RIR indicators
    if string.find(response_str, "rdap%.arin%.net") or string.find(response_str, "arin%.net") then
        return "ARIN (North America)"
    elseif string.find(response_str, "rdap%.ripe%.net") or string.find(response_str, "rdap%.db%.ripe%.net") or string.find(response_str, "ripe%.net") then
        return "RIPE NCC (Europe, Middle East, Central Asia)"
    elseif string.find(response_str, "rdap%.apnic%.net") or string.find(response_str, "apnic%.net") then
        return "APNIC (Asia-Pacific)"
    elseif string.find(response_str, "rdap%.lacnic%.net") or string.find(response_str, "lacnic%.net") then
        return "LACNIC (Latin America & Caribbean)"
    elseif string.find(response_str, "rdap%.afrinic%.net") or string.find(response_str, "afrinic%.net") then
        return "AFRINIC (Africa)"
    end
    
    return "Unknown RIR"
end

-- Determine which RIR should handle an IP address based on IP ranges
local function determine_rir_for_ip(ip)
    if not is_valid_ipv4(ip) then
        -- For IPv6, we'd need more complex logic, but for now return nil to use bootstrap
        return nil
    end
    
    -- Extract first octet to determine likely RIR
    local first_octet = tonumber(string.match(ip, "^(%d+)"))
    if not first_octet then return nil end
    
    -- Rough IP range assignments (these are approximate)
    -- ARIN: 7.0.0.0-7.255.255.255, 23.0.0.0-23.255.255.255, 50.0.0.0-50.255.255.255, etc.
    -- RIPE: 5.0.0.0-5.255.255.255, 31.0.0.0-31.255.255.255, 37.0.0.0-37.255.255.255, 46.0.0.0-46.255.255.255, 51.0.0.0-51.255.255.255, 62.0.0.0-62.255.255.255, 77.0.0.0-77.255.255.255, 78.0.0.0-78.255.255.255, 79.0.0.0-79.255.255.255, 80.0.0.0-80.255.255.255, 81.0.0.0-81.255.255.255, 82.0.0.0-82.255.255.255, 83.0.0.0-83.255.255.255, 84.0.0.0-84.255.255.255, 85.0.0.0-85.255.255.255, 86.0.0.0-86.255.255.255, 87.0.0.0-87.255.255.255, 88.0.0.0-88.255.255.255, 89.0.0.0-89.255.255.255, 90.0.0.0-90.255.255.255, 91.0.0.0-91.255.255.255, 92.0.0.0-92.255.255.255, 93.0.0.0-93.255.255.255, 94.0.0.0-94.255.255.255, 95.0.0.0-95.255.255.255, 109.0.0.0-109.255.255.255, 178.0.0.0-178.255.255.255, 185.0.0.0-185.255.255.255, 188.0.0.0-188.255.255.255, 193.0.0.0-193.255.255.255, 194.0.0.0-194.255.255.255, 195.0.0.0-195.255.255.255, 212.0.0.0-212.255.255.255, 213.0.0.0-213.255.255.255, 217.0.0.0-217.255.255.255
    -- APNIC: 1.0.0.0-1.255.255.255, 14.0.0.0-14.255.255.255, 27.0.0.0-27.255.255.255, 36.0.0.0-36.255.255.255, 39.0.0.0-39.255.255.255, 42.0.0.0-42.255.255.255, 49.0.0.0-49.255.255.255, 58.0.0.0-58.255.255.255, 59.0.0.0-59.255.255.255, 60.0.0.0-60.255.255.255, 61.0.0.0-61.255.255.255, 101.0.0.0-101.255.255.255, 103.0.0.0-103.255.255.255, 106.0.0.0-106.255.255.255, 110.0.0.0-110.255.255.255, 111.0.0.0-111.255.255.255, 112.0.0.0-112.255.255.255, 113.0.0.0-113.255.255.255, 114.0.0.0-114.255.255.255, 115.0.0.0-115.255.255.255, 116.0.0.0-116.255.255.255, 117.0.0.0-117.255.255.255, 118.0.0.0-118.255.255.255, 119.0.0.0-119.255.255.255, 120.0.0.0-120.255.255.255, 121.0.0.0-121.255.255.255, 122.0.0.0-122.255.255.255, 123.0.0.0-123.255.255.255, 124.0.0.0-124.255.255.255, 125.0.0.0-125.255.255.255, 150.0.0.0-150.255.255.255, 175.0.0.0-175.255.255.255, 180.0.0.0-180.255.255.255, 182.0.0.0-182.255.255.255, 183.0.0.0-183.255.255.255, 202.0.0.0-202.255.255.255, 203.0.0.0-203.255.255.255, 210.0.0.0-210.255.255.255, 211.0.0.0-211.255.255.255, 218.0.0.0-218.255.255.255, 219.0.0.0-219.255.255.255, 220.0.0.0-220.255.255.255, 221.0.0.0-221.255.255.255, 222.0.0.0-222.255.255.255, 223.0.0.0-223.255.255.255
    
    -- For 195.x.x.x, this is typically RIPE NCC
    if first_octet == 195 then
        return "https://rdap.db.ripe.net/ip/"
    end
    
    -- This is a simplified heuristic - in practice, we should use the bootstrap server
    -- or query each RIR, but for now return nil to use bootstrap
    return nil
end

local function lookup_ip_rdap(ip)
    if not is_valid_ip(ip) then
        return nil, "Invalid IP address: " .. tostring(ip)
    end
    
    -- Check cache first
    local cached = cache_get("rdap_ip", ip)
    if cached then
        log_message("Using cached RDAP data for IP: " .. ip)
        -- Make sure cached data has raw response for fallback extraction
        if not cached._raw_response and cached.raw then
            cached._raw_response = cached.raw
        end
        return cached, nil
    end
    
    -- Try RDAP bootstrap server first
    local url = CONFIG.RDAP_BOOTSTRAP_URL .. "/ip/" .. ip
    log_message("Querying RDAP bootstrap for IP: " .. ip .. " at URL: " .. url)
    
    local response, err = http_get(url)
    local rir_url = determine_rir_for_ip(ip)
    
    -- If bootstrap fails and we can determine the RIR, try direct RIR endpoint
    if (err or not response or response == "") and rir_url then
        log_message("Bootstrap failed, trying direct RIR endpoint: " .. rir_url .. ip)
        url = rir_url .. ip
        response, err = http_get(url)
    end
    
    -- If still failing, try common RIR endpoints as fallback
    if (err or not response or response == "") then
        local rir_endpoints = {
            "https://rdap.db.ripe.net/ip/",  -- RIPE NCC
            "https://rdap.arin.net/registry/ip/",  -- ARIN
            "https://rdap.apnic.net/ip/",  -- APNIC
            "https://rdap.lacnic.net/rdap/ip/",  -- LACNIC
            "https://rdap.afrinic.net/rdap/ip/"  -- AFRINIC
        }
        
        for _, endpoint in ipairs(rir_endpoints) do
            log_message("Trying RIR endpoint: " .. endpoint .. ip)
            url = endpoint .. ip
            response, err = http_get(url)
            if not err and response and response ~= "" then
                log_message("Success with endpoint: " .. endpoint)
                break
            end
        end
    end
    
    if err then
        -- Provide more helpful error message
        return nil, "RDAP lookup failed for IP " .. ip .. ": " .. err .. "\n\nTroubleshooting:\n- Check internet connectivity\n- Verify IP address format\n- The IP may not be registered in any RIR database"
    end
    
    if not response or response == "" then
        return nil, "RDAP returned empty response for IP: " .. ip .. "\n\nTried multiple RIR endpoints. The IP may not be registered or the RIR servers may be temporarily unavailable."
    end
    
    local data = parse_json(response)
    if not data then
        -- Return raw response if JSON parsing fails, might still be useful
        log_message("Warning: Failed to parse RDAP response as JSON")
        -- Try to extract basic info from raw response
        local raw_data = {raw = response, _parse_error = true}
        -- Try to extract IP range from raw response
        local start_ip = string.match(response, '"startAddress"%s*:%s*"([^"]+)"')
        local end_ip = string.match(response, '"endAddress"%s*:%s*"([^"]+)"')
        if start_ip and end_ip then
            raw_data.startAddress = start_ip
            raw_data.endAddress = end_ip
        end
        -- Detect RIR from raw response
        raw_data._detected_rir = detect_rir(nil, response)
        return raw_data, nil
    end
    
    -- Check for RDAP error responses
    if data.errorCode or (data.title and string.find(string.lower(data.title or ""), "error")) then
        local error_msg = data.title or data.message or "Unknown error"
        return nil, "RDAP error: " .. error_msg
    end
    
    -- Detect and store which RIR provided this response
    data._detected_rir = detect_rir(data, response)
    log_message("Detected RIR: " .. data._detected_rir)
    
    -- Store raw response for fallback extraction
    data._raw_response = response
    
    -- Cache the result
    cache_set("rdap_ip", ip, data)
    
    return data, nil
end

local function format_rdap_ip_result(data, ip, raw_response)
    if not data then return "No data available" end
    
    local result = "=== IP Registration Info (RDAP) ===\n\n"
    
    -- Store raw response for fallback extraction (try multiple sources)
    local response = raw_response or data._raw_response or data.raw or ""
    
    -- Show which RIR provided the data
    if data._detected_rir then
        result = result .. "Source Registry: " .. data._detected_rir .. "\n\n"
    end
    
    -- Handle raw/unparsed JSON
    if data.raw then
        result = result .. "Raw Response (JSON parsing failed):\n"
        result = result .. string.sub(data.raw, 1, 1000) .. "\n"
        if data.startAddress and data.endAddress then
            result = result .. "\nExtracted IP Range: " .. data.startAddress .. " - " .. data.endAddress .. "\n"
        end
        return result
    end
    
    -- Extract basic network information
    if data.startAddress and data.endAddress then
        result = result .. "IP Range: " .. data.startAddress .. " - " .. data.endAddress .. "\n"
    end
    
    -- Extract CIDR notation (important for APNIC and other RIRs)
    if data.cidr0_cidrs and data.cidr0_cidrs[1] then
        result = result .. "CIDR: " .. (data.cidr0_cidrs[1].v4prefix or data.cidr0_cidrs[1].v6prefix or "N/A") .. "\n"
    elseif data.cidr then
        result = result .. "CIDR: " .. data.cidr .. "\n"
    end
    
    -- Extract country code if available (APNIC includes this)
    if data.country then
        result = result .. "Country: " .. data.country .. "\n"
    end
    
    if data.name then
        result = result .. "Network Name: " .. data.name .. "\n"
    end
    
    if data.handle then
        result = result .. "Handle: " .. data.handle .. "\n"
    end
    
    if data.type then
        result = result .. "Type: " .. data.type .. "\n"
    end
    
    if data.netType then
        result = result .. "Net Type: " .. data.netType .. "\n"
    end
    
    if data.parentHandle then
        result = result .. "Parent Handle: " .. data.parentHandle .. "\n"
    end
    
    if data.status then
        result = result .. "Status: " .. (type(data.status) == "table" and table.concat(data.status, ", ") or tostring(data.status)) .. "\n"
    end
    
    -- Extract abuse contact information prominently
    local abuse_contacts = {}
    local other_entities = {}
    
    -- Helper function to extract contact info from entity
    local function extract_entity_info(entity)
        local info = {}
        if entity.vcardArray and entity.vcardArray[2] then
            local vcard = entity.vcardArray[2]
            for j, item in ipairs(vcard) do
                if type(item) == "table" and #item >= 3 then
                    local value = item[3]
                    -- Skip placeholder "text" values
                    if value and tostring(value):lower() ~= "text" and tostring(value) ~= "" then
                        if item[1] == "fn" then
                            info.name = value
                        elseif item[1] == "org" then
                            info.org = value
                        elseif item[1] == "email" then
                            info.email = value
                        elseif item[1] == "tel" then
                            info.phone = value
                        elseif item[1] == "adr" then
                            local addr = value
                            if type(addr) == "table" then
                                addr = table.concat(addr, ", ")
                            end
                            -- Skip if address is just "text"
                            if tostring(addr):lower() ~= "text" and tostring(addr) ~= "" then
                                info.address = addr
                            end
                        end
                    end
                end
            end
        end
        -- Also check for abuse email in remarks
        if entity.remarks then
            for _, remark in ipairs(entity.remarks) do
                if remark.description then
                    local desc = type(remark.description) == "table" and table.concat(remark.description, " ") or tostring(remark.description)
                    local email = string.match(desc, "([%w%._%-]+@[%w%._%-]+%.[%w%._%-]+)")
                    if email then
                        info.email = info.email or email
                    end
                end
            end
        end
        return info
    end
    
    if data.entities then
        for i, entity in ipairs(data.entities) do
            local is_abuse = false
            if entity.roles then
                local roles = type(entity.roles) == "table" and entity.roles or {entity.roles}
                for _, role in ipairs(roles) do
                    local role_lower = string.lower(tostring(role))
                    if string.find(role_lower, "abuse") then
                        is_abuse = true
                        break
                    end
                end
            end
            
            if is_abuse then
                table.insert(abuse_contacts, entity)
            else
                table.insert(other_entities, entity)
            end
        end
    end
    
    -- Also check if entities is a table but not an array (might be indexed differently)
    if type(data.entities) == "table" and not data.entities[1] then
        -- Try to iterate as a hash table
        for key, entity in pairs(data.entities) do
            if type(entity) == "table" then
                local is_abuse = false
                if entity.roles then
                    local roles = type(entity.roles) == "table" and entity.roles or {entity.roles}
                    for _, role in ipairs(roles) do
                        local role_lower = string.lower(tostring(role))
                        if string.find(role_lower, "abuse") then
                            is_abuse = true
                            break
                        end
                    end
                end
                
                if is_abuse then
                    table.insert(abuse_contacts, entity)
                else
                    table.insert(other_entities, entity)
                end
            end
        end
    end
    
    -- Display abuse contacts prominently
    if #abuse_contacts > 0 then
        result = result .. "\n--- Abuse Contact ---\n"
        local has_abuse_data = false
        for i, entity in ipairs(abuse_contacts) do
            local info = extract_entity_info(entity)
            local entity_has_data = false
            
            if info.name and tostring(info.name):lower() ~= "text" then
                result = result .. "Name: " .. info.name .. "\n"
                entity_has_data = true
            end
            if info.org and tostring(info.org):lower() ~= "text" then
                result = result .. "Organization: " .. info.org .. "\n"
                entity_has_data = true
            end
            if info.email and tostring(info.email):lower() ~= "text" then
                result = result .. "Email: " .. info.email .. "\n"
                entity_has_data = true
            end
            if info.phone and tostring(info.phone):lower() ~= "text" then
                result = result .. "Phone: " .. info.phone .. "\n"
                entity_has_data = true
            end
            if info.address and tostring(info.address):lower() ~= "text" then
                result = result .. "Address: " .. info.address .. "\n"
                entity_has_data = true
            end
            
            if not entity_has_data then
                result = result .. "No abuse contact data available\n"
            end
            
            if i < #abuse_contacts then
                result = result .. "\n"
            end
            has_abuse_data = has_abuse_data or entity_has_data
        end
        if not has_abuse_data then
            result = result .. "No abuse contact information available\n"
        end
    else
        result = result .. "\n--- Abuse Contact ---\n"
        result = result .. "No abuse contact information available\n"
    end
    
    -- Always try fallback extraction from raw JSON response
    -- This handles cases where the JSON parser didn't extract entities properly
    local response_str = response or data._raw_response or data.raw or ""
    
    if response_str and response_str ~= "" and #abuse_contacts == 0 then
        log_message("Attempting fallback extraction of abuse contact from raw response")
        
        -- Multiple patterns to try for extracting abuse contact
        local abuse_email = nil
        local abuse_phone = nil
        local abuse_org = nil
        
        -- Pattern 1: "roles": ["abuse"] ... "email": "abuse@example.com" (within same object, flexible spacing)
        abuse_email = string.match(response_str, '"roles"%s*:%s*%[%s*"abuse"[^}]*"email"%s*:%s*"([^"]+)"')
        
        -- Pattern 2: Look for "abuse" role, then find email in nearby text (more flexible, handles nested structures)
        if not abuse_email then
            -- Find all occurrences of "abuse" role
            local start_pos = 1
            while true do
                local abuse_pos = string.find(response_str, '"roles"%s*:%s*%[%s*"abuse"', start_pos)
                if not abuse_pos then break end
                
                -- Look for email within next 1000 characters (handles nested JSON)
                local search_area = string.sub(response_str, abuse_pos, math.min(abuse_pos + 1000, string.len(response_str)))
                abuse_email = string.match(search_area, '"email"%s*:%s*"([^"]+)"')
                if abuse_email then break end
                
                start_pos = abuse_pos + 1
            end
        end
        
        -- Pattern 3: Look for abuse-c role (alternative naming used by some RIRs)
        if not abuse_email then
            abuse_email = string.match(response_str, '"roles"%s*:%s*%[%s*"abuse%-c"[^}]*"email"%s*:%s*"([^"]+)"')
        end
        
        -- Pattern 4: Look for any entity with abuse in role name (case insensitive search in raw string)
        if not abuse_email then
            -- Convert to lowercase for case-insensitive search
            local response_lower = string.lower(response_str)
            local start_pos = 1
            while true do
                local abuse_pos = string.find(response_lower, '"roles"%s*:%s*%[%s*"[^"]*abuse[^"]*"', start_pos)
                if not abuse_pos then break end
                
                -- Find corresponding position in original string and search for email
                local search_area = string.sub(response_str, abuse_pos, math.min(abuse_pos + 1500, string.len(response_str)))
                abuse_email = string.match(search_area, '"email"%s*:%s*"([^"]+)"')
                if abuse_email then break end
                
                start_pos = abuse_pos + 1
            end
        end
        
        -- Pattern 5: Look for abuse@ email addresses anywhere in the response
        if not abuse_email then
            for email in string.gmatch(response_str, '"([%w%._%-]*abuse[%w%._%-]*@[%w%._%-]+%.[%w%._%-]+)"') do
                abuse_email = email
                break
            end
        end
        
        -- Pattern 6: Check remarks field for abuse contact information
        if not abuse_email then
            for remark_text in string.gmatch(response_str, '"remarks"%s*:%s*%[%s*{[^}]*"description"%s*:%s*%[%s*"([^"]+)"') do
                -- Look for email in remark description
                local email = string.match(remark_text, "([%w%._%-]+@[%w%._%-]+%.[%w%._%-]+)")
                if email and string.find(string.lower(remark_text), "abuse") then
                    abuse_email = email
                    break
                end
            end
        end
        
        -- Pattern 7: Look for abuse contact in notices (some RIRs use this)
        if not abuse_email then
            for notice_text in string.gmatch(response_str, '"notices"%s*:%s*%[%s*{[^}]*"description"%s*:%s*%[%s*"([^"]+)"') do
                local email = string.match(notice_text, "([%w%._%-]+@[%w%._%-]+%.[%w%._%-]+)")
                if email and string.find(string.lower(notice_text), "abuse") then
                    abuse_email = email
                    break
                end
            end
        end
        
        -- Pattern 8: Look for direct abuseContact field on the network object
        if not abuse_email then
            abuse_email = string.match(response_str, '"abuseContact"%s*:%s*"([^"]+)"')
        end
        
        -- Pattern 9: Look for abuseMailbox field (used by some RIRs)
        if not abuse_email then
            abuse_email = string.match(response_str, '"abuseMailbox"%s*:%s*"([^"]+)"')
        end
        
        -- Pattern 10: Extract from vcardArray structure directly (bypass entities parsing)
        if not abuse_email then
            -- Look for vcardArray that contains abuse-related info
            for vcard_section in string.gmatch(response_str, '"vcardArray"%s*:%s*%[%s*%[%s*%[%s*"([^"]+)"[^]]*%]%s*%]%s*%]') do
                if string.find(string.lower(vcard_section), "abuse") then
                    -- Found abuse-related vcard, now extract email
                    local email_match = string.match(response_str, '"vcardArray"%s*:%s*%[%s*%[%s*%[%s*"[^"]*"[^]]*%]%s*%]%s*%[%s*%[%s*"email"[^]]*"([^"]+)"')
                    if email_match then
                        abuse_email = email_match
                        break
                    end
                end
            end
        end
        
        -- Extract phone and org if email found
        if abuse_email then
            local email_pos = string.find(response_str, '"email"%s*:%s*"([^"]*)"', string.find(response_str, abuse_email) or 0)
            if email_pos then
                -- Search around the email position
                local search_start = math.max(1, email_pos - 500)
                local search_end = math.min(string.len(response_str), email_pos + 500)
                local search_area = string.sub(response_str, search_start, search_end)
                
                abuse_phone = string.match(search_area, '"tel"%s*:%s*"([^"]+)"')
                abuse_org = string.match(search_area, '"org"%s*:%s*"([^"]+)"')
            end
        end
        
        if abuse_email then
            result = result .. "\n--- Abuse Contact ---\n"
            if abuse_org then
                result = result .. "Organization: " .. abuse_org .. "\n"
            end
            result = result .. "Email: " .. abuse_email .. "\n"
            if abuse_phone then
                result = result .. "Phone: " .. abuse_phone .. "\n"
            end
            log_message("Successfully extracted abuse contact: " .. abuse_email)
        else
            log_message("Could not find abuse contact in response (response length: " .. string.len(response_str) .. ")")
        end
    end
    
    -- Display other registration entities
    if #other_entities > 0 then
        result = result .. "\n--- Registration Entities ---\n"
        for i, entity in ipairs(other_entities) do
            if entity.roles then
                result = result .. "\nRole: " .. (type(entity.roles) == "table" and table.concat(entity.roles, ", ") or tostring(entity.roles)) .. "\n"
            end
            if entity.vcardArray and entity.vcardArray[2] then
                local vcard = entity.vcardArray[2]
                local has_data = false
                for j, item in ipairs(vcard) do
                    if type(item) == "table" and #item >= 3 then
                        local value = item[3]
                        -- Skip placeholder "text" values
                        if value and tostring(value):lower() ~= "text" and tostring(value) ~= "" then
                            has_data = true
                            if item[1] == "fn" then
                                result = result .. "Name: " .. value .. "\n"
                            elseif item[1] == "org" then
                                result = result .. "Organization: " .. value .. "\n"
                            elseif item[1] == "adr" then
                                local addr = value
                                if type(addr) == "table" then
                                    addr = table.concat(addr, ", ")
                                end
                                if tostring(addr):lower() ~= "text" and tostring(addr) ~= "" then
                                    result = result .. "Address: " .. addr .. "\n"
                                end
                            elseif item[1] == "email" then
                                result = result .. "Email: " .. value .. "\n"
                            elseif item[1] == "tel" then
                                result = result .. "Phone: " .. value .. "\n"
                            end
                        end
                    end
                end
                if not has_data then
                    result = result .. "Contact information: No data available\n"
                end
            end
            -- Also check for simple object properties
            if entity.objectClassName then
                result = result .. "Object Class: " .. entity.objectClassName .. "\n"
            end
        end
    end
    
    -- Extract and display registration and last changed dates prominently
    local registration_date = nil
    local last_changed_date = nil
    local last_modified_date = nil
    
    if data.events then
        for i, event in ipairs(data.events) do
            if event.eventAction and event.eventDate then
                local action = string.lower(event.eventAction or "")
                if string.find(action, "registration") or string.find(action, "registered") then
                    registration_date = event.eventDate
                elseif string.find(action, "last changed") or string.find(action, "last changed") or string.find(action, "changed") then
                    last_changed_date = event.eventDate
                elseif string.find(action, "last modified") or string.find(action, "modified") then
                    last_modified_date = event.eventDate
                end
            end
        end
        
        -- Display registration date prominently
        if registration_date then
            result = result .. "\n--- Registration Date ---\n"
            result = result .. "Registered: " .. registration_date .. "\n"
        end
        
        -- Display last changed date prominently
        if last_changed_date then
            result = result .. "\n--- Last Changed ---\n"
            result = result .. "Last Changed: " .. last_changed_date .. "\n"
        elseif last_modified_date then
            result = result .. "\n--- Last Modified ---\n"
            result = result .. "Last Modified: " .. last_modified_date .. "\n"
        end
        
        -- Show all other events if any
        local other_events = {}
        for i, event in ipairs(data.events) do
            if event.eventAction and event.eventDate then
                local action = string.lower(event.eventAction or "")
                if not string.find(action, "registration") and 
                   not string.find(action, "registered") and
                   not string.find(action, "last changed") and
                   not string.find(action, "changed") and
                   not string.find(action, "last modified") and
                   not string.find(action, "modified") then
                    table.insert(other_events, event)
                end
            end
        end
        
        if #other_events > 0 then
            result = result .. "\n--- Other Events ---\n"
            for i, event in ipairs(other_events) do
                result = result .. event.eventAction .. ": " .. event.eventDate .. "\n"
            end
        end
    end
    
    -- Extract links (RDAP references)
    if data.links then
        result = result .. "\n--- Related Resources ---\n"
        for i, link in ipairs(data.links) do
            if link.rel and link.href then
                result = result .. link.rel .. ": " .. link.href .. "\n"
            end
        end
    end
    
    -- Show RDAP conformance
    if data.rdapConformance then
        result = result .. "\n--- RDAP Conformance ---\n"
        result = result .. (type(data.rdapConformance) == "table" and table.concat(data.rdapConformance, ", ") or tostring(data.rdapConformance)) .. "\n"
    end
    
    -- If we have raw data but couldn't parse it well, show a note
    if not data.startAddress and not data.name and not data.entities then
        result = result .. "\nNote: Limited data extracted. Full response may contain more information.\n"
        result = result .. "Try querying the RIR directly or check the raw JSON response.\n"
    end
    
    return result
end

local function ip_rdap_callback(fieldname, ...)
    local fields = {...}
    local ip_raw = get_field_value(fieldname, "display", fields)
    
    if not ip_raw then
        show_error_window("RDAP IP Lookup", "Could not extract IP address from packet")
        return
    end
    
    -- Extract IP address from the field value (might contain hostname)
    local ip = extract_ip_from_string(ip_raw)
    if not ip then
        show_error_window("RDAP IP Lookup", "Could not extract valid IP address from: " .. ip_raw)
        return
    end
    
    -- Check if this is an RFC 1918 private address (IPv4 only for now)
    if is_rfc1918_private(ip) then
        local formatted = format_rfc1918_info(ip)
        show_result_window("Private IP Address: " .. ip, formatted)
        return
    end
    
    local data, err = lookup_ip_rdap(ip)
    if err then
        show_error_window("RDAP IP Lookup Error", "Error querying RDAP:\n" .. err)
        return
    end
    
    local formatted = format_rdap_ip_result(data, ip, data._raw_response)
    show_result_window_with_buttons("IP Registration Info (RDAP): " .. ip, formatted, "IP RDAP", ip)
end

-------------------------------------------------
-- IP Reputation Module (AbuseIPDB)
-------------------------------------------------

local function lookup_ip_reputation(ip)
    -- Debug: Log API key status (first 10 chars only for security)
    local key_preview = CONFIG.ABUSEIPDB_API_KEY ~= "" and string.sub(CONFIG.ABUSEIPDB_API_KEY, 1, 10) .. "..." or "not set"
    log_message("AbuseIPDB API key status: " .. key_preview)
    
    if not CONFIG.ABUSEIPDB_ENABLED or CONFIG.ABUSEIPDB_API_KEY == "" then
        return nil, "AbuseIPDB API key not configured.\n\n" ..
                    "Option 1: Create file ~/.ask/ABUSEIPDB_API_KEY.txt with your API key\n" ..
                    "Option 2: Set environment variable: export ABUSEIPDB_API_KEY=\"your_key\"\n" ..
                    "Option 3: Launch Wireshark from terminal with env var set\n\n" ..
                    "Get free API key at: https://www.abuseipdb.com/api"
    end
    
    if not is_valid_ip(ip) then
        return nil, "Invalid IP address"
    end
    
    -- Check cache first
    local cached = cache_get("abuseipdb", ip)
    if cached then
        log_message("Using cached AbuseIPDB data for IP: " .. ip)
        return cached, nil
    end
    
    local url = string.format(
        "https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90&verbose",
        ip
    )
    
    log_message("Querying AbuseIPDB for IP: " .. ip)
    log_message("AbuseIPDB API key length: " .. (CONFIG.ABUSEIPDB_API_KEY and string.len(CONFIG.ABUSEIPDB_API_KEY) or 0) .. " characters")
    
    local headers = {
        ["Key"] = CONFIG.ABUSEIPDB_API_KEY,
        ["Accept"] = "application/json"
    }
    
    local response, err = http_get(url, headers)
    if err then
        return nil, err
    end
    
    if not response or response == "" then
        return nil, "AbuseIPDB API returned empty response"
    end
    
    local data = parse_json(response)
    if not data then
        return nil, "Failed to parse AbuseIPDB response. Raw response: " .. string.sub(response, 1, 200)
    end
    
    -- Check for API errors
    if data.errors then
        local error_msg = "AbuseIPDB API Error"
        if type(data.errors) == "table" then
            error_msg = error_msg .. ": " .. table.concat(data.errors, ", ")
        else
            error_msg = error_msg .. ": " .. tostring(data.errors)
        end
        
        -- Add helpful troubleshooting info for auth errors
        if string.find(tostring(data.errors), "401") or 
           string.find(tostring(data.errors), "Authentication") or
           string.find(tostring(data.errors), "missing") or
           string.find(tostring(data.errors), "incorrect") then
            error_msg = error_msg .. "\n\nTroubleshooting:\n" ..
                       "1. Verify your API key is correct (APIv2 key, not APIv1)\n" ..
                       "2. Check file ~/.ask/ABUSEIPDB_API_KEY.txt contains only the key (no extra spaces/newlines)\n" ..
                       "3. Get a new APIv2 key from: https://www.abuseipdb.com/api\n" ..
                       "4. Restart Wireshark after updating the key file"
        end
        
        return nil, error_msg
    end
    
    -- Cache the result
    cache_set("abuseipdb", ip, data)
    
    return data, nil
end

local function format_abuseipdb_result(data, ip)
    ip = ip or "unknown"
    
    if not data then 
        return "=== IP Reputation (AbuseIPDB) ===\n\n" ..
               "Query: " .. ip .. "\n\n" ..
               "No entry found in AbuseIPDB for this IP address.\n" ..
               "This could mean:\n" ..
               "- The IP has not been reported to AbuseIPDB\n" ..
               "- The IP is clean/legitimate\n" ..
               "- The IP is too new to have reports"
    end
    
    if not data.data then 
        return "=== IP Reputation (AbuseIPDB) ===\n\n" ..
               "Query: " .. ip .. "\n\n" ..
               "No entry found in AbuseIPDB for this IP address.\n" ..
               "This could mean:\n" ..
               "- The IP has not been reported to AbuseIPDB\n" ..
               "- The IP is clean/legitimate\n" ..
               "- The IP is too new to have reports"
    end
    
    local d = data.data
    local result = "=== IP Reputation (AbuseIPDB) ===\n\n"
    result = result .. "Query: " .. ip .. "\n\n"
    
    if d.ipAddress then
        result = result .. "IP Address: " .. d.ipAddress .. "\n"
    end
    
    if d.isPublic ~= nil then
        result = result .. "Is Public: " .. tostring(d.isPublic) .. "\n"
    end
    
    if d.ipVersion then
        result = result .. "IP Version: " .. tostring(d.ipVersion) .. "\n"
    end
    
    if d.isWhitelisted ~= nil then
        result = result .. "Whitelisted: " .. tostring(d.isWhitelisted) .. "\n"
    end
    
    if d.abuseConfidenceScore ~= nil then
        result = result .. "\n--- Reputation Score ---\n"
        result = result .. "Abuse Confidence Score: " .. tostring(d.abuseConfidenceScore) .. "%\n"
        if d.abuseConfidenceScore >= 75 then
            result = result .. "Status: HIGH RISK\n"
        elseif d.abuseConfidenceScore >= 25 then
            result = result .. "Status: MEDIUM RISK\n"
        else
            result = result .. "Status: LOW RISK\n"
        end
    end
    
    if d.usageType then
        result = result .. "\nUsage Type: " .. d.usageType .. "\n"
    end
    
    if d.isp then
        result = result .. "ISP: " .. d.isp .. "\n"
    end
    
    if d.domain then
        result = result .. "Domain: " .. d.domain .. "\n"
    end
    
    if d.hostnames then
        result = result .. "\n--- Hostnames ---\n"
        for i, hostname in ipairs(d.hostnames) do
            result = result .. hostname .. "\n"
        end
    end
    
    if d.countryCode then
        result = result .. "\nCountry Code: " .. d.countryCode .. "\n"
    end
    
    if d.countryName then
        result = result .. "Country: " .. d.countryName .. "\n"
    end
    
    if d.totalReports then
        result = result .. "\nTotal Reports: " .. tostring(d.totalReports) .. "\n"
    end
    
    if d.numDistinctUsers then
        result = result .. "Distinct Reporters: " .. tostring(d.numDistinctUsers) .. "\n"
    end
    
    if d.lastReportedAt then
        result = result .. "Last Reported: " .. d.lastReportedAt .. "\n"
    end
    
    return result
end

local function ip_reputation_callback(fieldname, ...)
    local fields = {...}
    local ip_raw = get_field_value(fieldname, "display", fields)
    
    if not ip_raw then
        show_error_window("IP Reputation Lookup", "Could not extract IP address from packet")
        return
    end
    
    -- Extract IP address from the field value (might contain hostname)
    local ip = extract_ip_from_string(ip_raw)
    if not ip then
        show_error_window("IP Reputation Lookup", "Could not extract valid IP address from: " .. ip_raw)
        return
    end
    
    -- Check if this is an RFC 1918 private address
    if is_rfc1918_private(ip) then
        local formatted = format_rfc1918_info(ip)
        show_result_window("Private IP Address: " .. ip, formatted)
        return
    end
    
    local data, err = lookup_ip_reputation(ip)
    if err then
        show_error_window("IP Reputation Error", "Error querying AbuseIPDB:\n" .. err)
        return
    end
    
    local formatted = format_abuseipdb_result(data, ip)
    show_result_window_with_buttons("IP Reputation: " .. ip, formatted, "AbuseIPDB", ip)
end

-------------------------------------------------
-- URL Categorization Module (urlscan.io)
-------------------------------------------------

local function lookup_url_reputation(url)
    if not CONFIG.URLSCAN_ENABLED then
        return nil, "urlscan.io is disabled in configuration"
    end
    
    if not is_valid_url(url) then
        return nil, "Invalid URL format"
    end
    
    -- Extract domain from URL for more reliable searching
    -- urlscan.io query syntax doesn't handle colons well in url: queries
    local domain = string.match(url, "https?://([^/]+)")
    if not domain then
        domain = string.match(url, "([^/]+)")
    end
    -- Remove port if present
    domain = string.match(domain or url, "([^:]+)")
    
    -- URL encode the domain for the query parameter
    local domain_encoded = url_encode(domain or url)
    
    -- Search by domain first (more reliable than full URL due to query syntax)
    -- Also try searching by full URL if domain search doesn't work
    local search_url = string.format(
        "https://urlscan.io/api/v1/search/?q=domain:%s",
        domain_encoded
    )
    
    -- If we want to search by exact URL, we need to quote it properly
    -- But urlscan.io's query parser is finicky, so domain search is safer
    
    log_message("Searching urlscan.io for URL: " .. url)
    log_message("Extracted domain: " .. (domain or "N/A"))
    log_message("urlscan.io search URL: " .. search_url)
    
    local headers = {}
    if CONFIG.URLSCAN_API_KEY ~= "" then
        headers["API-Key"] = CONFIG.URLSCAN_API_KEY
    end
    
    local response, err = http_get(search_url, headers)
    if err then
        return nil, err
    end
    
    if not response or response == "" then
        return nil, "urlscan.io returned empty response"
    end
    
    -- Check if response contains an error message (handle escaped quotes)
    if string.find(response, '"error"') or string.find(response, '"message"') or string.find(response, '"detail"') then
        -- Try to extract error message with better handling of escaped quotes
        -- Pattern: "message": "text" or "message": "text with \"escaped\" quotes"
        local error_msg = nil
        
        -- Try simple extraction first
        error_msg = string.match(response, '"message"%s*:%s*"([^"]*)"') or 
                   string.match(response, '"error"%s*:%s*"([^"]*)"') or
                   string.match(response, '"detail"%s*:%s*"([^"]*)"')
        
        -- If simple extraction didn't work, try to find the message value more carefully
        if not error_msg then
            -- Look for "message": "..." pattern, handling escaped quotes
            local msg_start = string.find(response, '"message"%s*:%s*"')
            if msg_start then
                -- Find the closing quote, skipping escaped quotes
                local pos = msg_start + 11 -- After "message": "
                local msg_end = pos
                while msg_end <= string.len(response) do
                    local char = string.sub(response, msg_end, msg_end)
                    if char == '"' and string.sub(response, msg_end - 1, msg_end - 1) ~= "\\" then
                        break
                    end
                    msg_end = msg_end + 1
                    if msg_end > pos + 500 then break end -- Safety limit
                end
                if msg_end > pos then
                    error_msg = string.sub(response, pos, msg_end - 1)
                    -- Unescape common sequences
                    error_msg = string.gsub(error_msg, '\\"', '"')
                    error_msg = string.gsub(error_msg, '\\\\', '\\')
                end
            end
        end
        
        if error_msg and error_msg ~= "" then
            -- Check if it's a query syntax error
            if string.find(error_msg, "Expected") or string.find(error_msg, "found") then
                return nil, "urlscan.io Query Syntax Error: " .. error_msg .. "\n\n" ..
                          "This usually means the search query format is invalid.\n" ..
                          "The plugin now searches by domain instead of full URL to avoid this issue.\n" ..
                          "If this error persists, the domain may contain invalid characters."
            end
            return nil, "urlscan.io API Error: " .. error_msg
        end
    end
    
    -- Store raw response for fallback parsing
    local raw_response = response
    
    local search_data = parse_json(response)
    if not search_data then
        -- Check if it's a JSON parsing error
        if string.find(response, "Expected") or string.find(response, "parse") then
            return nil, "Failed to parse urlscan.io JSON response.\n\n" ..
                       "The response contains malformed JSON or special characters.\n" ..
                       "This might indicate:\n" ..
                       "- API returned an error response\n" ..
                       "- Response contains escaped characters\n" ..
                       "- Network/proxy issues\n\n" ..
                       "Response preview: " .. string.sub(response, 1, 300)
        end
        
        -- Provide more helpful error message with response preview
        local preview = string.sub(response, 1, 200)
        return nil, "Failed to parse urlscan.io search response.\n\n" ..
                   "Response preview: " .. preview .. "\n\n" ..
                   "This might indicate:\n" ..
                   "- Invalid URL format\n" ..
                   "- API rate limiting\n" ..
                   "- Network connectivity issues\n" ..
                   "- Malformed JSON response"
    end
    
    -- Log the structure for debugging
    if search_data.results then
        log_message("urlscan.io results type: " .. type(search_data.results))
        if type(search_data.results) == "table" then
            log_message("urlscan.io results length: " .. #search_data.results)
            -- Check what keys exist
            local key_count = 0
            for k, v in pairs(search_data.results) do
                key_count = key_count + 1
                if key_count <= 5 then
                    log_message("urlscan.io results key[" .. tostring(key_count) .. "]: " .. tostring(k) .. " = " .. type(v))
                end
            end
            log_message("urlscan.io results total keys: " .. key_count)
            
            -- Try to access first element
            if search_data.results[1] then
                local first_result = search_data.results[1]
                log_message("urlscan.io first result[1] type: " .. type(first_result))
                if type(first_result) == "table" then
                    local keys = {}
                    for k, v in pairs(first_result) do
                        table.insert(keys, tostring(k) .. "(" .. type(v) .. ")")
                    end
                    log_message("urlscan.io first result keys: " .. table.concat(keys, ", "))
                end
            end
        end
    end
    
    -- If we have results, get the most recent one
    if search_data.results and #search_data.results > 0 then
        local result = search_data.results[1]
        if result and type(result) == "table" and result._id then
            -- Fetch detailed result
            local detail_url = "https://urlscan.io/api/v1/result/" .. result._id
            log_message("Fetching detailed result from: " .. detail_url)
            local detail_response, detail_err = http_get(detail_url, headers)
            if not detail_err and detail_response then
                local detail_data = parse_json(detail_response)
                if detail_data then
                    log_message("Successfully retrieved detailed result")
                    return detail_data, nil
                else
                    log_message("Failed to parse detailed result")
                end
            else
                log_message("Failed to fetch detailed result: " .. (detail_err or "unknown error"))
            end
        end
    end
    
    -- If search_data doesn't have proper results array, try to extract scan IDs from raw JSON
    if search_data and search_data.results and type(search_data.results) == "table" and #search_data.results == 0 then
        -- Try to extract scan IDs directly from raw JSON string as fallback
        log_message("Attempting to extract scan IDs from raw JSON string")
        local scan_ids = {}
        
        -- Look for "_id" fields in the results array
        for scan_id in string.gmatch(raw_response, '"_id"%s*:%s*"([^"]+)"') do
            table.insert(scan_ids, scan_id)
        end
        
        if #scan_ids > 0 then
            log_message("Extracted " .. #scan_ids .. " scan IDs from raw JSON")
            -- Create a simple results array with just IDs
            local simple_results = {}
            for i, id in ipairs(scan_ids) do
                if i <= 10 then -- Limit to first 10
                    table.insert(simple_results, {_id = id})
                end
            end
            search_data.results = simple_results
            search_data._extracted_ids = true -- Flag that we extracted IDs
        end
    end
    
    -- Return search results if no detailed result available
    return search_data, nil
end

local function format_urlscan_result(data)
    if not data then return "No data available" end
    
    local result = "=== URL Categorization & Reputation (urlscan.io) ===\n\n"
    
    -- Handle search results format
    if data.results and type(data.results) == "table" then
        -- Check if results is an array (has numeric indices starting from 1)
        local results_array = {}
        local result_count = 0
        
        -- Check if it's a proper array by testing first few indices
        if data.results[1] ~= nil then
            -- It's an array - use ipairs
            for i, scan in ipairs(data.results) do
                if type(scan) == "table" then
                    table.insert(results_array, scan)
                    result_count = result_count + 1
                end
            end
        else
            -- It's an object - the JSON parser didn't parse the array correctly
            -- The simple parser might have merged all objects into one
            -- Try to extract individual scan results
            log_message("Results is an object, attempting to extract scan data")
            
            -- Check if the object itself looks like a scan result
            if data.results._id or (data.results.task and type(data.results.task) == "table") then
                -- The results object itself might be a single scan result
                table.insert(results_array, data.results)
                result_count = 1
            else
                -- Try to find scan-like objects in the results table
                -- Filter out string keys that are metadata fields
                local metadata_keys = {
                    task = true, visibility = true, public = true, method = true, manual = true,
                    url = true, domain = true, ip = true, asn = true, country = true,
                    total = true, has_more = true, took = true
                }
                for k, v in pairs(data.results) do
                    -- Skip known metadata/aggregate fields
                    if type(k) == "string" and metadata_keys[k] then
                        -- Skip metadata fields
                    elseif type(v) == "table" then
                        -- Check if it looks like a scan result
                        if v._id or (v.task and type(v.task) == "table") or (v.verdicts and type(v.verdicts) == "table") then
                            table.insert(results_array, v)
                            result_count = result_count + 1
                        end
                    elseif type(k) == "number" or (type(k) == "string" and tonumber(k)) then
                        -- Numeric key - likely an array index
                        if type(v) == "table" then
                            table.insert(results_array, v)
                            result_count = result_count + 1
                        end
                    end
                end
            end
        end
        
        if result_count > 0 then
            result = result .. "Found " .. result_count .. " scan result(s)\n\n"
            local display_count = math.min(5, result_count)
            for i = 1, display_count do
                local scan = results_array[i]
                if scan then
                    result = result .. "--- Scan #" .. i .. " ---\n"
                    
                    -- Check various possible field locations
                    if type(scan) == "table" then
                        -- Check for _id field
                        if scan._id then
                            result = result .. "Scan ID: " .. scan._id .. "\n"
                        end
                        
                        -- Check for task.url
                        if scan.task and type(scan.task) == "table" and scan.task.url then
                            result = result .. "URL: " .. scan.task.url .. "\n"
                        elseif scan.url then
                            result = result .. "URL: " .. scan.url .. "\n"
                        end
                        
                        -- Check for task.time
                        if scan.task and type(scan.task) == "table" and scan.task.time then
                            result = result .. "Scanned: " .. scan.task.time .. "\n"
                        elseif scan.time then
                            result = result .. "Scanned: " .. scan.time .. "\n"
                        elseif scan.timestamp then
                            result = result .. "Scanned: " .. scan.timestamp .. "\n"
                        end
                        
                        -- Check for verdicts (security assessment)
                        if scan.verdicts and type(scan.verdicts) == "table" then
                            result = result .. "\n--- Security Verdicts ---\n"
                            
                            if scan.verdicts.urlscan and type(scan.verdicts.urlscan) == "table" then
                                if scan.verdicts.urlscan.score then
                                    local score = scan.verdicts.urlscan.score
                                    result = result .. "urlscan Score: " .. score .. "\n"
                                    result = result .. "  (Range: -100 legitimate to +100 malicious)\n"
                                    if score >= 50 then
                                        result = result .. "  ⚠ HIGH RISK - Likely malicious\n"
                                    elseif score >= 25 then
                                        result = result .. "  ⚠ MEDIUM RISK - Suspicious\n"
                                    elseif score >= 0 then
                                        result = result .. "  ℹ LOW RISK - Possibly suspicious\n"
                                    else
                                        result = result .. "  ✓ Likely legitimate\n"
                                    end
                                end
                            end
                            
                            if scan.verdicts.overall and type(scan.verdicts.overall) == "table" then
                                if scan.verdicts.overall.malicious ~= nil then
                                    result = result .. "Overall Malicious: " .. tostring(scan.verdicts.overall.malicious) .. "\n"
                                end
                                if scan.verdicts.overall.categories and type(scan.verdicts.overall.categories) == "table" then
                                    result = result .. "Categories: " .. table.concat(scan.verdicts.overall.categories, ", ") .. "\n"
                                end
                                if scan.verdicts.overall.brands and type(scan.verdicts.overall.brands) == "table" then
                                    result = result .. "Brands Detected: " .. table.concat(scan.verdicts.overall.brands, ", ") .. "\n"
                                end
                            end
                            
                            if scan.verdicts.community and type(scan.verdicts.community) == "table" then
                                if scan.verdicts.community.malicious ~= nil then
                                    result = result .. "Community Verdict: " .. tostring(scan.verdicts.community.malicious) .. "\n"
                                end
                            end
                        end
                        
                        -- Check for page information
                        if scan.page and type(scan.page) == "table" then
                            result = result .. "\n--- Page Information ---\n"
                            if scan.page.url then
                                result = result .. "Final URL: " .. scan.page.url .. "\n"
                            end
                            if scan.page.domain then
                                result = result .. "Domain: " .. scan.page.domain .. "\n"
                            end
                            if scan.page.ip then
                                result = result .. "IP Address: " .. scan.page.ip .. "\n"
                            end
                            if scan.page.country then
                                result = result .. "Country: " .. scan.page.country .. "\n"
                            end
                            if scan.page.asn then
                                result = result .. "ASN: " .. scan.page.asn .. "\n"
                            end
                            if scan.page.asnname then
                                result = result .. "ASN Name: " .. scan.page.asnname .. "\n"
                            end
                            if scan.page.status then
                                result = result .. "HTTP Status: " .. scan.page.status .. "\n"
                            end
                            if scan.page.title then
                                result = result .. "Page Title: " .. scan.page.title .. "\n"
                            end
                        end
                        
                        -- Check for lists (domains, IPs, URLs found in scan)
                        if scan.lists and type(scan.lists) == "table" then
                            result = result .. "\n--- Resources Found ---\n"
                            if scan.lists.domains and type(scan.lists.domains) == "table" and #scan.lists.domains > 0 then
                                local domain_count = math.min(5, #scan.lists.domains)
                                result = result .. "Domains (" .. #scan.lists.domains .. "): "
                                for i = 1, domain_count do
                                    result = result .. scan.lists.domains[i]
                                    if i < domain_count then result = result .. ", " end
                                end
                                if #scan.lists.domains > domain_count then
                                    result = result .. " ..."
                                end
                                result = result .. "\n"
                            end
                            if scan.lists.ips and type(scan.lists.ips) == "table" and #scan.lists.ips > 0 then
                                local ip_count = math.min(5, #scan.lists.ips)
                                result = result .. "IPs (" .. #scan.lists.ips .. "): "
                                for i = 1, ip_count do
                                    result = result .. scan.lists.ips[i]
                                    if i < ip_count then result = result .. ", " end
                                end
                                if #scan.lists.ips > ip_count then
                                    result = result .. " ..."
                                end
                                result = result .. "\n"
                            end
                        end
                        
                        -- Check for stats
                        if scan.stats and type(scan.stats) == "table" then
                            result = result .. "\n--- Scan Statistics ---\n"
                            if scan.stats.requests then
                                result = result .. "HTTP Requests: " .. tostring(scan.stats.requests) .. "\n"
                            end
                            if scan.stats.secureRequests then
                                result = result .. "HTTPS Requests: " .. tostring(scan.stats.secureRequests) .. "\n"
                            end
                            if scan.stats.redirects then
                                result = result .. "Redirects: " .. tostring(scan.stats.redirects) .. "\n"
                            end
                        end
                        
                        -- Add link to view full scan
                        if scan._id then
                            result = result .. "\nView full scan: https://urlscan.io/result/" .. scan._id .. "\n"
                        end
                        
                        -- If we have a scan ID but no other data, provide a link
                        if scan._id then
                            if not (scan.task and scan.task.url) and not scan.url then
                                result = result .. "View scan: https://urlscan.io/result/" .. scan._id .. "\n"
                            end
                        end
                        
                        -- If we only have minimal data (just ID), make it clear
                        if scan._id and not scan.task and not scan.url and not scan.verdicts then
                            result = result .. "(Limited data - view full scan online for details)\n"
                        end
                    end
                    
                    result = result .. "\n"
                end
            end
            
            if result_count > 5 then
                result = result .. "... and " .. (result_count - 5) .. " more scan(s)\n"
            end
            
            return result
        else
            -- No results found after filtering - the JSON parser likely didn't parse the array correctly
            result = result .. "Found scan results in response, but unable to parse the data structure.\n\n"
            result = result .. "This is a known limitation when using the simple JSON parser with\n"
            result = result .. "complex arrays of objects from urlscan.io.\n\n"
            result = result .. "The API returned data, but the parser couldn't extract individual scans.\n\n"
            result = result .. "Suggestions:\n"
            result = result .. "• Install a Lua JSON library (e.g., lua-json) for better parsing\n"
            result = result .. "• View results directly at: https://urlscan.io/search/\n"
            result = result .. "• Check Wireshark console logs for detailed structure information\n\n"
            result = result .. "Note: The search was successful - urlscan.io found scan results,\n"
            result = result .. "but the plugin needs a proper JSON library to display them."
            return result
        end
    end
    
    -- Handle detailed result format (from /api/v1/result/{id})
    if data.task then
        result = result .. "--- Scan Details ---\n"
        if data.task.url then
            result = result .. "Scanned URL: " .. data.task.url .. "\n"
        end
        if data.task.time then
            result = result .. "Scan Time: " .. data.task.time .. "\n"
        end
        if data.task.method then
            result = result .. "Method: " .. data.task.method .. "\n"
        end
        if data.task.visibility then
            result = result .. "Visibility: " .. data.task.visibility .. "\n"
        end
    end
    
    if data.verdicts then
        result = result .. "\n--- Security Verdicts ---\n"
        
        if data.verdicts.urlscan and type(data.verdicts.urlscan) == "table" then
            if data.verdicts.urlscan.score then
                local score = data.verdicts.urlscan.score
                result = result .. "urlscan Score: " .. score .. "\n"
                result = result .. "  (Range: -100 legitimate to +100 malicious)\n"
                if score >= 50 then
                    result = result .. "  ⚠ HIGH RISK - Likely malicious\n"
                elseif score >= 25 then
                    result = result .. "  ⚠ MEDIUM RISK - Suspicious\n"
                elseif score >= 0 then
                    result = result .. "  ℹ LOW RISK - Possibly suspicious\n"
                else
                    result = result .. "  ✓ Likely legitimate\n"
                end
            end
        end
        
        if data.verdicts.overall and type(data.verdicts.overall) == "table" then
            if data.verdicts.overall.malicious ~= nil then
                result = result .. "Overall Malicious: " .. tostring(data.verdicts.overall.malicious) .. "\n"
            end
            if data.verdicts.overall.categories and type(data.verdicts.overall.categories) == "table" then
                result = result .. "Categories: " .. table.concat(data.verdicts.overall.categories, ", ") .. "\n"
            end
            if data.verdicts.overall.brands and type(data.verdicts.overall.brands) == "table" then
                result = result .. "Brands Detected: " .. table.concat(data.verdicts.overall.brands, ", ") .. "\n"
            end
        end
        
        if data.verdicts.community and type(data.verdicts.community) == "table" then
            if data.verdicts.community.malicious ~= nil then
                result = result .. "Community Verdict: " .. tostring(data.verdicts.community.malicious) .. "\n"
            end
        end
        
        if data.verdicts.engines and type(data.verdicts.engines) == "table" then
            result = result .. "\n--- Security Engine Verdicts ---\n"
            local engine_count = 0
            for engine, verdict in pairs(data.verdicts.engines) do
                if type(verdict) == "table" and verdict.malicious ~= nil then
                    engine_count = engine_count + 1
                    if engine_count <= 10 then
                        result = result .. engine .. ": " .. tostring(verdict.malicious) .. "\n"
                    end
                end
            end
            if engine_count > 10 then
                result = result .. "... and " .. (engine_count - 10) .. " more engines\n"
            end
        end
    end
    
    -- Lists (domains, IPs, URLs found in scan)
    if data.lists and type(data.lists) == "table" then
        result = result .. "\n--- Resources Found in Scan ---\n"
        if data.lists.domains and type(data.lists.domains) == "table" and #data.lists.domains > 0 then
            local domain_count = math.min(10, #data.lists.domains)
            result = result .. "Domains (" .. #data.lists.domains .. "):\n"
            for i = 1, domain_count do
                result = result .. "  • " .. data.lists.domains[i] .. "\n"
            end
            if #data.lists.domains > domain_count then
                result = result .. "  ... and " .. (#data.lists.domains - domain_count) .. " more\n"
            end
        end
        if data.lists.ips and type(data.lists.ips) == "table" and #data.lists.ips > 0 then
            local ip_count = math.min(10, #data.lists.ips)
            result = result .. "\nIP Addresses (" .. #data.lists.ips .. "):\n"
            for i = 1, ip_count do
                result = result .. "  • " .. data.lists.ips[i] .. "\n"
            end
            if #data.lists.ips > ip_count then
                result = result .. "  ... and " .. (#data.lists.ips - ip_count) .. " more\n"
            end
        end
        if data.lists.urls and type(data.lists.urls) == "table" and #data.lists.urls > 0 then
            local url_count = math.min(5, #data.lists.urls)
            result = result .. "\nURLs (" .. #data.lists.urls .. "):\n"
            for i = 1, url_count do
                result = result .. "  • " .. data.lists.urls[i] .. "\n"
            end
            if #data.lists.urls > url_count then
                result = result .. "  ... and " .. (#data.lists.urls - url_count) .. " more\n"
            end
        end
    end
    
    -- Stats
    if data.stats and type(data.stats) == "table" then
        result = result .. "\n--- Scan Statistics ---\n"
        if data.stats.requests then
            result = result .. "Total HTTP Requests: " .. tostring(data.stats.requests) .. "\n"
        end
        if data.stats.secureRequests then
            result = result .. "HTTPS Requests: " .. tostring(data.stats.secureRequests) .. "\n"
        end
        if data.stats.redirects then
            result = result .. "Redirects: " .. tostring(data.stats.redirects) .. "\n"
        end
        if data.stats.consoleMsgs then
            result = result .. "Console Messages: " .. tostring(data.stats.consoleMsgs) .. "\n"
        end
    end
    
    -- Meta information (processor output)
    if data.meta and type(data.meta) == "table" then
        result = result .. "\n--- Additional Intelligence ---\n"
        if data.meta.processors and type(data.meta.processors) == "table" then
            if data.meta.processors.google and type(data.meta.processors.google) == "table" then
                if data.meta.processors.google.safe then
                    result = result .. "Google Safe Browsing: " .. tostring(data.meta.processors.google.safe) .. "\n"
                end
            end
        end
    end
    
    -- Add link to view full scan if we have task data
    if data.task and data.task.uuid then
        result = result .. "\n--- Full Report ---\n"
        result = result .. "View complete scan: https://urlscan.io/result/" .. data.task.uuid .. "\n"
        if data.task.screenshotURL then
            result = result .. "Screenshot: " .. data.task.screenshotURL .. "\n"
        end
        if data.task.domURL then
            result = result .. "DOM: " .. data.task.domURL .. "\n"
        end
    end
    
    if data.page then
        result = result .. "\n--- Page Information ---\n"
        if data.page.url then
            result = result .. "Final URL: " .. data.page.url .. "\n"
        end
        if data.page.domain then
            result = result .. "Domain: " .. data.page.domain .. "\n"
        end
        if data.page.apexDomain then
            result = result .. "Apex Domain: " .. data.page.apexDomain .. "\n"
        end
        if data.page.ip then
            result = result .. "IP Address: " .. data.page.ip .. "\n"
        end
        if data.page.country then
            result = result .. "Country: " .. data.page.country .. "\n"
        end
        if data.page.asn then
            result = result .. "ASN: " .. data.page.asn .. "\n"
        end
        if data.page.asnname then
            result = result .. "ASN Name: " .. data.page.asnname .. "\n"
        end
        if data.page.status then
            result = result .. "HTTP Status: " .. data.page.status .. "\n"
        end
        if data.page.title then
            result = result .. "Page Title: " .. data.page.title .. "\n"
        end
        if data.page.mimeType then
            result = result .. "MIME Type: " .. data.page.mimeType .. "\n"
        end
        if data.page.redirected then
            result = result .. "Redirected: Yes\n"
        end
        if data.page.tlsIssuer then
            result = result .. "TLS Issuer: " .. data.page.tlsIssuer .. "\n"
        end
        if data.page.tlsValidDays then
            result = result .. "TLS Valid Days: " .. data.page.tlsValidDays .. "\n"
        end
        if data.page.domain then
            result = result .. "Domain: " .. data.page.domain .. "\n"
        end
        if data.page.ip then
            result = result .. "IP: " .. data.page.ip .. "\n"
        end
        if data.page.country then
            result = result .. "Country: " .. data.page.country .. "\n"
        end
    end
    
    -- Blocklists (if available)
    if data.lists and type(data.lists) == "table" then
        local has_blocklists = false
        if data.lists.ip and type(data.lists.ip) == "table" and #data.lists.ip > 0 then
            has_blocklists = true
        elseif data.lists.domain and type(data.lists.domain) == "table" and #data.lists.domain > 0 then
            has_blocklists = true
        elseif data.lists.url and type(data.lists.url) == "table" and #data.lists.url > 0 then
            has_blocklists = true
        end
        
        if has_blocklists then
            result = result .. "\n--- Blocklist Matches ---\n"
            if data.lists.ip and type(data.lists.ip) == "table" and #data.lists.ip > 0 then
                result = result .. "IP Blocklists: " .. table.concat(data.lists.ip, ", ") .. "\n"
            end
            if data.lists.domain and type(data.lists.domain) == "table" and #data.lists.domain > 0 then
                result = result .. "Domain Blocklists: " .. table.concat(data.lists.domain, ", ") .. "\n"
            end
            if data.lists.url and type(data.lists.url) == "table" and #data.lists.url > 0 then
                result = result .. "URL Blocklists: " .. table.concat(data.lists.url, ", ") .. "\n"
            end
        end
    end
    
    -- Use case information
    result = result .. "\n--- Use Case ---\n"
    result = result .. "urlscan.io provides dynamic URL analysis by:\n"
    result = result .. "• Executing JavaScript in a sandboxed browser\n"
    result = result .. "• Capturing all network requests and responses\n"
    result = result .. "• Analyzing behavior and content\n"
    result = result .. "• Checking against security engines and blocklists\n\n"
    result = result .. "Perfect for investigating:\n"
    result = result .. "• Suspicious URLs from phishing emails\n"
    result = result .. "• Unknown links in network traffic\n"
    result = result .. "• Malware C2 domains and URLs\n"
    result = result .. "• Potentially malicious websites\n"
    
    return result
end

local function url_reputation_callback(...)
    local fields = {...}
    local url = get_field_value("http.request.full_uri", "display", fields)
    
    if not url then
        show_error_window("URL Reputation Lookup", "Could not extract URL from packet")
        return
    end
    
    local data, err = lookup_url_reputation(url)
    if err then
        show_error_window("URL Reputation Error", "Error querying urlscan.io:\n" .. err)
        return
    end
    
    local formatted = format_urlscan_result(data)
    show_result_window_with_buttons("URL Reputation: " .. url, formatted, "urlscan.io", url)
end

-------------------------------------------------
-- VirusTotal Module
-------------------------------------------------

local function lookup_virustotal_ip(ip)
    -- Debug: Log API key status (first 10 chars only for security)
    local key_preview = CONFIG.VIRUSTOTAL_API_KEY ~= "" and string.sub(CONFIG.VIRUSTOTAL_API_KEY, 1, 10) .. "..." or "not set"
    log_message("VirusTotal API key status: " .. key_preview)
    
    if not CONFIG.VIRUSTOTAL_ENABLED or CONFIG.VIRUSTOTAL_API_KEY == "" then
        return nil, "VirusTotal API key not configured.\n\n" ..
                    "Option 1: Create file ~/.ask/VIRUSTOTAL_API_KEY.txt with your API key\n" ..
                    "Option 2: Set environment variable: export VIRUSTOTAL_API_KEY=\"your_key\"\n" ..
                    "Option 3: Launch Wireshark from terminal with env var set\n\n" ..
                    "Get free API key at: https://www.virustotal.com/gui/join-us"
    end
    
    if not is_valid_ip(ip) then
        return nil, "Invalid IP address"
    end
    
    -- Check cache first
    local cached = cache_get("virustotal_ip", ip)
    if cached then
        log_message("Using cached VirusTotal data for IP: " .. ip)
        return cached, nil
    end
    
    local url = string.format("https://www.virustotal.com/api/v3/ip_addresses/%s", ip)
    log_message("Querying VirusTotal for IP: " .. ip)
    
    -- Trim API key to remove any whitespace/newlines
    local api_key = string.gsub(CONFIG.VIRUSTOTAL_API_KEY, "^%s+", "")  -- Remove leading whitespace
    api_key = string.gsub(api_key, "%s+$", "")  -- Remove trailing whitespace
    api_key = string.gsub(api_key, "\n", "")  -- Remove newlines
    api_key = string.gsub(api_key, "\r", "")  -- Remove carriage returns
    
    log_message("VirusTotal API key length after trimming: " .. string.len(api_key) .. " characters")
    
    local headers = {
        ["x-apikey"] = api_key,
        ["Accept"] = "application/json"
    }
    
    local response, err = http_get(url, headers)
    if err then
        -- Check if error mentions API key
        if string.find(err, "API key") or string.find(err, "Wrong API key") or string.find(err, "authentication") then
            return nil, "VirusTotal API Error: " .. err .. "\n\n" ..
                       "Troubleshooting:\n" ..
                       "1. Verify your API key is correct at: https://www.virustotal.com/gui/user/YOUR_USERNAME/apikey\n" ..
                       "2. Check file ~/.ask/VIRUSTOTAL_API_KEY.txt contains only the key (no extra spaces/newlines)\n" ..
                       "3. Make sure you're using a VirusTotal API v3 key (64 characters)\n" ..
                       "4. Verify the API key hasn't expired or been revoked\n" ..
                       "5. Check if your API key has the required permissions for IP lookups"
        end
        return nil, err
    end
    
    local data = parse_json(response)
    if not data then
        -- Check if response contains an error about API key
        if response and (string.find(response, "Wrong API key") or string.find(response, "Invalid API key") or string.find(response, "authentication")) then
            return nil, "VirusTotal API Error: Wrong API key\n\n" ..
                       "Troubleshooting:\n" ..
                       "1. Verify your API key is correct at: https://www.virustotal.com/gui/user/YOUR_USERNAME/apikey\n" ..
                       "2. Check file ~/.ask/VIRUSTOTAL_API_KEY.txt contains only the key (no extra spaces/newlines)\n" ..
                       "3. Make sure you're using a VirusTotal API v3 key (64 characters)\n" ..
                       "4. Verify the API key hasn't expired or been revoked\n" ..
                       "5. Check if your API key has the required permissions for IP lookups\n\n" ..
                       "Response: " .. string.sub(response or "", 1, 200)
        end
        return nil, "Failed to parse VirusTotal response"
    end
    
    if data.error then
        local error_msg = tostring(data.error.message or data.error.code or "Unknown error")
        if string.find(error_msg, "API key") or string.find(error_msg, "Wrong") or string.find(error_msg, "authentication") then
            return nil, "VirusTotal API Error: " .. error_msg .. "\n\n" ..
                       "Troubleshooting:\n" ..
                       "1. Verify your API key is correct at: https://www.virustotal.com/gui/user/YOUR_USERNAME/apikey\n" ..
                       "2. Check file ~/.ask/VIRUSTOTAL_API_KEY.txt contains only the key (no extra spaces/newlines)\n" ..
                       "3. Make sure you're using a VirusTotal API v3 key (64 characters)\n" ..
                       "4. Verify the API key hasn't expired or been revoked\n" ..
                       "5. Check if your API key has the required permissions for IP lookups"
        end
        return nil, "API Error: " .. error_msg
    end
    
    -- Cache the result
    cache_set("virustotal_ip", ip, data)
    
    return data, nil
end

local function lookup_virustotal_domain(domain)
    if not CONFIG.VIRUSTOTAL_ENABLED or CONFIG.VIRUSTOTAL_API_KEY == "" then
        return nil, "VirusTotal API key not configured.\n\n" ..
                    "Option 1: Create file ~/.ask/VIRUSTOTAL_API_KEY.txt with your API key\n" ..
                    "Option 2: Set environment variable: export VIRUSTOTAL_API_KEY=\"your_key\"\n" ..
                    "Option 3: Launch Wireshark from terminal with env var set\n\n" ..
                    "Get free API key at: https://www.virustotal.com/gui/join-us"
    end
    
    if not is_valid_domain(domain) then
        return nil, "Invalid domain name"
    end
    
    -- Check cache first
    local cached = cache_get("virustotal_domain", domain)
    if cached then
        log_message("Using cached VirusTotal data for domain: " .. domain)
        return cached, nil
    end
    
    local url = string.format("https://www.virustotal.com/api/v3/domains/%s", domain)
    log_message("Querying VirusTotal for domain: " .. domain)
    
    local headers = {
        ["x-apikey"] = CONFIG.VIRUSTOTAL_API_KEY,
        ["Accept"] = "application/json"
    }
    
    local response, err = http_get(url, headers)
    if err then
        return nil, err
    end
    
    local data = parse_json(response)
    if not data then
        return nil, "Failed to parse VirusTotal response"
    end
    
    if data.error then
        return nil, "API Error: " .. tostring(data.error.message)
    end
    
    -- Cache the result
    cache_set("virustotal_domain", domain, data)
    
    return data, nil
end

local function lookup_virustotal_url(url)
    if not CONFIG.VIRUSTOTAL_ENABLED or CONFIG.VIRUSTOTAL_API_KEY == "" then
        return nil, "VirusTotal API key not configured.\n\n" ..
                    "Option 1: Create file ~/.ask/VIRUSTOTAL_API_KEY.txt with your API key\n" ..
                    "Option 2: Set environment variable: export VIRUSTOTAL_API_KEY=\"your_key\"\n" ..
                    "Option 3: Launch Wireshark from terminal with env var set\n\n" ..
                    "Get free API key at: https://www.virustotal.com/gui/join-us"
    end
    
    if not is_valid_url(url) then
        return nil, "Invalid URL format"
    end
    
    -- Check cache first
    local cached = cache_get("virustotal_url", url)
    if cached then
        log_message("Using cached VirusTotal data for URL: " .. url)
        return cached, nil
    end
    
    -- VirusTotal API v3 requires POST for URL submission
    local api_url = "https://www.virustotal.com/api/v3/urls"
    log_message("Querying VirusTotal for URL: " .. url)
    
    local headers = {
        ["x-apikey"] = CONFIG.VIRUSTOTAL_API_KEY,
        ["Accept"] = "application/json",
        ["Content-Type"] = "application/x-www-form-urlencoded"
    }
    
    -- URL needs to be URL-encoded for POST body
    local url_encoded = url_encode(url)
    local post_body = "url=" .. url_encoded
    
    local response, err = http_post(api_url, headers, post_body)
    if err then
        return nil, err
    end
    
    local data = parse_json(response)
    if not data then
        log_message("VirusTotal: Failed to parse JSON response. Response: " .. string.sub(response or "", 1, 500))
        return nil, "Failed to parse VirusTotal response"
    end
    
    if data.error then
        return nil, "API Error: " .. tostring(data.error.message or data.error)
    end
    
    -- Log response structure for debugging
    log_message("VirusTotal response received:")
    if data.data then
        log_message("  data.data exists")
        if data.data.id then
            log_message("  data.data.id: " .. tostring(data.data.id))
        end
        if data.data.type then
            log_message("  data.data.type: " .. tostring(data.data.type))
        end
    else
        log_message("  data.data does NOT exist")
        if type(data) == "table" then
            local keys = {}
            for k, _ in pairs(data) do
                table.insert(keys, tostring(k))
            end
            log_message("  Response keys: " .. table.concat(keys, ", "))
        else
            log_message("  Response is not a table")
        end
    end
    
    -- Cache the result
    cache_set("virustotal_url", url, data)
    
    return data, nil
end

local function format_virustotal_ip_result(data, ip)
    ip = ip or "unknown"
    
    if not data then 
        return "=== IP Reputation (VirusTotal) ===\n\n" ..
               "Query: " .. ip .. "\n\n" ..
               "No entry found in VirusTotal for this IP address.\n" ..
               "This could mean:\n" ..
               "- The IP has not been analyzed by VirusTotal\n" ..
               "- The IP is clean/legitimate\n" ..
               "- The IP is too new to have analysis results"
    end
    
    if not data.data then 
        return "=== IP Reputation (VirusTotal) ===\n\n" ..
               "Query: " .. ip .. "\n\n" ..
               "No entry found in VirusTotal for this IP address.\n" ..
               "This could mean:\n" ..
               "- The IP has not been analyzed by VirusTotal\n" ..
               "- The IP is clean/legitimate\n" ..
               "- The IP is too new to have analysis results"
    end
    
    local d = data.data
    local result = "=== IP Reputation (VirusTotal) ===\n\n"
    result = result .. "Query: " .. ip .. "\n\n"
    
    if d.id then
        result = result .. "IP Address: " .. d.id .. "\n"
    end
    
    if d.attributes then
        local attrs = d.attributes
        
        if attrs.last_analysis_stats then
            result = result .. "\n--- Analysis Statistics ---\n"
            local stats = attrs.last_analysis_stats
            result = result .. "Harmless: " .. tostring(stats.harmless or 0) .. "\n"
            result = result .. "Malicious: " .. tostring(stats.malicious or 0) .. "\n"
            result = result .. "Suspicious: " .. tostring(stats.suspicious or 0) .. "\n"
            result = result .. "Undetected: " .. tostring(stats.undetected or 0) .. "\n"
            
            local total = (stats.harmless or 0) + (stats.malicious or 0) + (stats.suspicious or 0) + (stats.undetected or 0)
            if total > 0 then
                local malicious_pct = math.floor(((stats.malicious or 0) / total) * 100)
                result = result .. "\nMalicious Rate: " .. malicious_pct .. "%\n"
                if malicious_pct >= 50 then
                    result = result .. "Status: HIGH RISK\n"
                elseif malicious_pct >= 25 then
                    result = result .. "Status: MEDIUM RISK\n"
                else
                    result = result .. "Status: LOW RISK\n"
                end
            end
        end
        
        if attrs.country then
            result = result .. "\nCountry: " .. attrs.country .. "\n"
        end
        
        if attrs.as_owner then
            result = result .. "AS Owner: " .. attrs.as_owner .. "\n"
        end
        
        if attrs.asn then
            result = result .. "ASN: " .. tostring(attrs.asn) .. "\n"
        end
        
        if attrs.last_analysis_date then
            result = result .. "\nLast Analysis: " .. os.date("%Y-%m-%d %H:%M:%S", attrs.last_analysis_date) .. "\n"
        end
        
        if attrs.reputation then
            result = result .. "Reputation Score: " .. tostring(attrs.reputation) .. "\n"
            result = result .. "(Range: -100 to 100, higher is better)\n"
        end
    end
    
    return result
end

local function format_virustotal_domain_result(data, domain)
    domain = domain or "unknown"
    
    if not data then 
        return "=== Domain Reputation (VirusTotal) ===\n\n" ..
               "Query: " .. domain .. "\n\n" ..
               "No entry found in VirusTotal for this domain.\n" ..
               "This could mean:\n" ..
               "- The domain has not been analyzed by VirusTotal\n" ..
               "- The domain is clean/legitimate\n" ..
               "- The domain is too new to have analysis results"
    end
    
    if not data.data then 
        return "=== Domain Reputation (VirusTotal) ===\n\n" ..
               "Query: " .. domain .. "\n\n" ..
               "No entry found in VirusTotal for this domain.\n" ..
               "This could mean:\n" ..
               "- The domain has not been analyzed by VirusTotal\n" ..
               "- The domain is clean/legitimate\n" ..
               "- The domain is too new to have analysis results"
    end
    
    local d = data.data
    local result = "=== Domain Reputation (VirusTotal) ===\n\n"
    result = result .. "Query: " .. domain .. "\n\n"
    
    if d.id then
        result = result .. "Domain: " .. d.id .. "\n"
    end
    
    if d.attributes then
        local attrs = d.attributes
        
        if attrs.last_analysis_stats then
            result = result .. "\n--- Analysis Statistics ---\n"
            local stats = attrs.last_analysis_stats
            result = result .. "Harmless: " .. tostring(stats.harmless or 0) .. "\n"
            result = result .. "Malicious: " .. tostring(stats.malicious or 0) .. "\n"
            result = result .. "Suspicious: " .. tostring(stats.suspicious or 0) .. "\n"
            result = result .. "Undetected: " .. tostring(stats.undetected or 0) .. "\n"
            
            local total = (stats.harmless or 0) + (stats.malicious or 0) + (stats.suspicious or 0) + (stats.undetected or 0)
            if total > 0 then
                local malicious_pct = math.floor(((stats.malicious or 0) / total) * 100)
                result = result .. "\nMalicious Rate: " .. malicious_pct .. "%\n"
            end
        end
        
        if attrs.categories then
            result = result .. "\n--- Categories ---\n"
            for category, _ in pairs(attrs.categories) do
                result = result .. category .. "\n"
            end
        end
        
        if attrs.reputation then
            result = result .. "\nReputation Score: " .. tostring(attrs.reputation) .. "\n"
        end
    end
    
    return result
end

local function virustotal_ip_callback(fieldname, ...)
    local fields = {...}
    local ip_raw = get_field_value(fieldname, "display", fields)
    
    if not ip_raw then
        show_error_window("VirusTotal IP Lookup", "Could not extract IP address from packet")
        return
    end
    
    -- Extract IP address from the field value (might contain hostname)
    local ip = extract_ip_from_string(ip_raw)
    if not ip then
        show_error_window("VirusTotal IP Lookup", "Could not extract valid IP address from: " .. ip_raw)
        return
    end
    
    -- Check if this is an RFC 1918 private address
    if is_rfc1918_private(ip) then
        local formatted = format_rfc1918_info(ip)
        show_result_window("Private IP Address: " .. ip, formatted)
        return
    end
    
    local data, err = lookup_virustotal_ip(ip)
    if err then
        show_error_window("VirusTotal Error", "Error querying VirusTotal:\n" .. err)
        return
    end
    
    local formatted = format_virustotal_ip_result(data, ip)
    show_result_window_with_buttons("VirusTotal IP: " .. ip, formatted, "VirusTotal IP", ip)
end

local function virustotal_domain_callback(...)
    local fields = {...}
    local domain = get_field_value("dns.qry.name", "value", fields)
    
    if not domain then
        show_error_window("VirusTotal Domain Lookup", "Could not extract domain name from packet")
        return
    end
    
    local data, err = lookup_virustotal_domain(domain)
    if err then
        show_error_window("VirusTotal Error", "Error querying VirusTotal:\n" .. err)
        return
    end
    
    local formatted = format_virustotal_domain_result(data, domain)
    show_result_window_with_buttons("VirusTotal Domain: " .. domain, formatted, "VirusTotal Domain", domain)
end

local function format_virustotal_url_result(data, url, analysis_data)
    url = url or "unknown"
    
    local result = "=== URL Reputation (VirusTotal) ===\n\n"
    result = result .. "URL: " .. url .. "\n\n"
    
    -- Check if we have analysis data (from polling)
    if analysis_data and analysis_data.data then
        local analysis = analysis_data.data
        result = result .. "--- Analysis Status ---\n"
        if analysis.status then
            result = result .. "Status: " .. analysis.status .. "\n"
        end
        
        if analysis.attributes then
            local attrs = analysis.attributes
            if attrs.stats then
                result = result .. "\n--- Analysis Statistics ---\n"
                local stats = attrs.stats
                result = result .. "Harmless: " .. tostring(stats.harmless or 0) .. "\n"
                result = result .. "Malicious: " .. tostring(stats.malicious or 0) .. "\n"
                result = result .. "Suspicious: " .. tostring(stats.suspicious or 0) .. "\n"
                result = result .. "Undetected: " .. tostring(stats.undetected or 0) .. "\n"
                
                local total = (stats.harmless or 0) + (stats.malicious or 0) + (stats.suspicious or 0) + (stats.undetected or 0)
                if total > 0 then
                    local malicious_pct = math.floor(((stats.malicious or 0) / total) * 100)
                    result = result .. "\nMalicious Rate: " .. malicious_pct .. "%\n"
                    if malicious_pct >= 50 then
                        result = result .. "⚠ Status: HIGH RISK\n"
                    elseif malicious_pct >= 25 then
                        result = result .. "⚠ Status: MEDIUM RISK\n"
                    elseif malicious_pct > 0 then
                        result = result .. "ℹ Status: LOW RISK\n"
                    else
                        result = result .. "✓ Status: CLEAN\n"
                    end
                end
            end
            
            if attrs.date then
                result = result .. "\nAnalysis Date: " .. os.date("%Y-%m-%d %H:%M:%S", attrs.date) .. "\n"
            end
        end
        
        if analysis.id then
            result = result .. "\nAnalysis ID: " .. analysis.id .. "\n"
            result = result .. "View on VirusTotal: https://www.virustotal.com/gui/url/" .. analysis.id .. "\n"
        end
    elseif data and data.data then
        -- We have URL data directly (existing scan)
        local url_data = data.data
        result = result .. "--- URL Information ---\n"
        if url_data.id then
            result = result .. "URL ID: " .. url_data.id .. "\n"
            result = result .. "View on VirusTotal: https://www.virustotal.com/gui/url/" .. url_data.id .. "\n"
        end
        
        if url_data.attributes then
            local attrs = url_data.attributes
            if attrs.last_analysis_stats then
                result = result .. "\n--- Last Analysis Statistics ---\n"
                local stats = attrs.last_analysis_stats
                result = result .. "Harmless: " .. tostring(stats.harmless or 0) .. "\n"
                result = result .. "Malicious: " .. tostring(stats.malicious or 0) .. "\n"
                result = result .. "Suspicious: " .. tostring(stats.suspicious or 0) .. "\n"
                result = result .. "Undetected: " .. tostring(stats.undetected or 0) .. "\n"
                
                local total = (stats.harmless or 0) + (stats.malicious or 0) + (stats.suspicious or 0) + (stats.undetected or 0)
                if total > 0 then
                    local malicious_pct = math.floor(((stats.malicious or 0) / total) * 100)
                    result = result .. "\nMalicious Rate: " .. malicious_pct .. "%\n"
                    if malicious_pct >= 50 then
                        result = result .. "⚠ Status: HIGH RISK\n"
                    elseif malicious_pct >= 25 then
                        result = result .. "⚠ Status: MEDIUM RISK\n"
                    elseif malicious_pct > 0 then
                        result = result .. "ℹ Status: LOW RISK\n"
                    else
                        result = result .. "✓ Status: CLEAN\n"
                    end
                end
            end
            
            if attrs.last_analysis_date then
                result = result .. "\nLast Analyzed: " .. os.date("%Y-%m-%d %H:%M:%S", attrs.last_analysis_date) .. "\n"
            end
            
            if attrs.reputation then
                result = result .. "Reputation Score: " .. tostring(attrs.reputation) .. "\n"
                result = result .. "(Range: -100 to 100, higher is better)\n"
            end
            
            if attrs.categories then
                result = result .. "\n--- Categories ---\n"
                local cats = {}
                for cat, _ in pairs(attrs.categories) do
                    table.insert(cats, cat)
                end
                if #cats > 0 then
                    result = result .. table.concat(cats, ", ") .. "\n"
                end
            end
            
            if attrs.title then
                result = result .. "\nPage Title: " .. attrs.title .. "\n"
            end
        end
    else
        result = result .. "No analysis data available.\n\n"
        result = result .. "The URL may be queued for analysis.\n"
        result = result .. "Check VirusTotal website for results."
    end
    
    return result
end

local function virustotal_url_callback(...)
    local fields = {...}
    local url = get_field_value("http.request.full_uri", "display", fields)
    
    if not url then
        show_error_window("VirusTotal URL Lookup", "Could not extract URL from packet")
        return
    end
    
    local data, err = lookup_virustotal_url(url)
    if err then
        show_error_window("VirusTotal Error", "Error querying VirusTotal:\n" .. err)
        return
    end
    
    -- VirusTotal URL API can return two types of responses:
    -- 1. Existing URL data (data.data.type == "url")
    -- 2. New analysis submission (data.data.type == "analysis")
    
    if not data then
        show_error_window("VirusTotal Error", "No data returned from VirusTotal API")
        return
    end
    
    -- Check if we have the expected response structure
    if data.data and data.data.id then
        local result_id = data.data.id
        local data_type = data.data.type or "unknown"
        
        local headers = {
            ["x-apikey"] = CONFIG.VIRUSTOTAL_API_KEY,
            ["Accept"] = "application/json"
        }
        
        if data_type == "analysis" then
            -- New analysis submitted - poll for results
            log_message("VirusTotal: New analysis submitted, polling for results...")
            local analysis_url = "https://www.virustotal.com/api/v3/analyses/" .. result_id
            
            -- Poll up to 5 times with increasing delays
            local max_attempts = 5
            local analysis_data = nil
            
            for attempt = 1, max_attempts do
                -- Wait before polling (longer wait for later attempts)
                if attempt > 1 then
                    local wait_time = attempt * 2 -- 2s, 4s, 6s, 8s, 10s
                    log_message("VirusTotal: Waiting " .. wait_time .. " seconds before polling attempt " .. attempt)
                    os.execute("sleep " .. wait_time)
                end
                
                local response, err2 = http_get(analysis_url, headers)
                if not err2 and response then
                    analysis_data = parse_json(response)
                    if analysis_data and analysis_data.data then
                        local status = analysis_data.data.status
                        log_message("VirusTotal: Analysis status: " .. (status or "unknown"))
                        
                        if status == "completed" then
                            log_message("VirusTotal: Analysis completed successfully")
                            break
                        elseif status == "queued" or status == "in-progress" then
                            log_message("VirusTotal: Analysis still in progress, will retry...")
                        else
                            -- Unknown status, break and show what we have
                            break
                        end
                    end
                end
            end
            
            -- Format and show results
            local formatted = format_virustotal_url_result(data, url, analysis_data)
            show_result_window_with_buttons("VirusTotal URL: " .. url, formatted, "VirusTotal URL", url)
        elseif data_type == "url" then
            -- Existing URL data - fetch full details
            log_message("VirusTotal: Found existing URL data")
            local url_detail_url = "https://www.virustotal.com/api/v3/urls/" .. result_id
            local response, err2 = http_get(url_detail_url, headers)
            
            if not err2 and response then
                local url_data = parse_json(response)
                if url_data then
                    local formatted = format_virustotal_url_result(url_data, url, nil)
                    show_result_window_with_buttons("VirusTotal URL: " .. url, formatted, "VirusTotal URL", url)
                    return
                end
            end
            
            -- Fallback: use the data we already have
            local formatted = format_virustotal_url_result(data, url, nil)
            show_result_window_with_buttons("VirusTotal URL: " .. url, formatted, "VirusTotal URL", url)
        else
            -- Unknown type, try to show what we have
            log_message("VirusTotal: Unknown data type: " .. tostring(data_type))
            local formatted = format_virustotal_url_result(data, url, nil)
            show_result_window_with_buttons("VirusTotal URL: " .. url, formatted, "VirusTotal URL", url)
        end
    else
        -- Response structure doesn't match expected format
        log_message("VirusTotal: Unexpected response structure")
        log_message("  data exists: " .. tostring(data ~= nil))
        log_message("  data.data exists: " .. tostring(data and data.data ~= nil))
        if data and data.data then
            log_message("  data.data.id exists: " .. tostring(data.data.id ~= nil))
        end
        
        -- Try to show what we have anyway
        local formatted = format_virustotal_url_result(data, url, nil)
        show_result_window_with_buttons("VirusTotal URL: " .. url, formatted, "VirusTotal URL", url)
    end
end

-------------------------------------------------
-- Shodan Module
-------------------------------------------------

local function lookup_shodan_ip(ip)
    local api_key = string.gsub(CONFIG.SHODAN_API_KEY or "", "%s+", "")
    ip = tostring(ip or ""):gsub("%s+", "")
    if not CONFIG.SHODAN_ENABLED or api_key == "" then
        return nil, "Shodan API key not configured.\n\n" ..
                    "Option 1: Create file ~/.ask/SHODAN_API_KEY.txt with your API key\n" ..
                    "Option 2: Set environment variable: export SHODAN_API_KEY=\"your_key\"\n" ..
                    "Option 3: Launch Wireshark from terminal with env var set\n\n" ..
                    "Get API key at: https://account.shodan.io/register"
    end
    
    if not is_valid_ip(ip) then
        return nil, "Invalid IP address"
    end
    
    -- Check cache first
    local cached = cache_get("shodan", ip)
    if cached then
        log_message("Using cached Shodan data for IP: " .. ip)
        return cached, nil
    end
    
    local encoded_ip = url_encode(ip)
    local url = string.format("https://api.shodan.io/shodan/host/%s?key=%s", encoded_ip, api_key)
    if not url or url == "" then
        return nil, "Shodan API Error: Invalid URL (empty). Check IP and API key formatting."
    end
    log_message("Querying Shodan for IP: " .. ip)
    
    local response, err = http_get(url, {
        ["Accept"] = "application/json",
        ["User-Agent"] = "ASK-Wireshark-Plugin/0.2.5"
    }, { allow_error_json = true })
    if err then
        return nil, "Shodan API Error: " .. err
    end
    
    if not response or response == "" then
        return nil, "Shodan API returned empty response"
    end
    
    -- Check for HTML error pages (Cloudflare, Azure, etc.) before parsing JSON
    -- IMPORTANT: Only check at the START of response, not embedded in JSON data
    local trimmed = string.gsub(response, "^%s+", "")
    local is_html = string.find(trimmed, "^<!DOCTYPE") or 
                   string.find(trimmed, "^<html") or 
                   string.find(trimmed, "^<HTML") or
                   string.find(trimmed, "^<head>") or
                   string.find(trimmed, "^<body>")
    
    -- Check for error page indicators (but only if not already JSON)
    local has_error_indicators = false
    if not is_html then
        -- Only check for error page text if we haven't already detected HTML tags
        local starts_with_json = string.find(trimmed, "^{")
        if not starts_with_json then
            -- Not JSON, so check for error page indicators
            has_error_indicators = string.find(response, "Microsoft Azure Web App") or
                                  string.find(response, "Site Not Configured") or
                                  string.find(response, "Error 404") or
                                  string.find(response, "403 Forbidden")
        end
    end
    
    if is_html or has_error_indicators then
        log_message("Shodan: Received HTML/error page (first 500 chars): " .. string.sub(response, 1, 500))
        return nil, "Shodan API Error: Invalid Response (HTML instead of JSON)\n\n" ..
                   "Received an HTML error page instead of JSON response.\n" ..
                   "Response preview: " .. string.sub(response, 1, 200) .. "\n\n" ..
                   "Common causes:\n" ..
                   "- API endpoint routing issue (Cloudflare/Azure error)\n" ..
                   "- Invalid or missing API key\n" ..
                   "- Rate limiting or access restrictions\n\n" ..
                   "Troubleshooting:\n" ..
                   "1. Verify your API key is correct at: https://account.shodan.io/\n" ..
                   "2. Check API key file: ~/.ask/SHODAN_API_KEY.txt (ensure no extra spaces/newlines)\n" ..
                   "3. Verify API key has proper permissions\n" ..
                   "4. Note: Shodan host lookup requires paid membership ($49+)\n" ..
                   "5. Try again in a few moments (may be temporary API issue)\n\n" ..
                   "Alternative: Use other ASK features (AbuseIPDB, VirusTotal, RDAP, IPinfo)"
    end
    
    -- Check if response looks like valid JSON (starts with { or [)
    local trimmed_response = string.gsub(response, "^%s+", "")
    if not string.find(trimmed_response, "^[%{%[]") then
        log_message("Shodan: Response doesn't look like JSON (first 500 chars): " .. string.sub(response, 1, 500))
        return nil, "Shodan API Error: Invalid Response Format\n\n" ..
                   "Response doesn't appear to be valid JSON.\n" ..
                   "Response preview: " .. string.sub(response, 1, 200) .. "\n\n" ..
                   "This usually indicates an API routing or configuration issue.\n" ..
                   "Please try again later or use alternative ASK features."
    end
    
    local data = parse_json(response)
    if not data then
        log_message("Shodan: Failed to parse JSON. Raw response (first 500 chars): " .. string.sub(response, 1, 500))
        return nil, "Failed to parse Shodan response.\n\n" ..
                   "Response preview: " .. string.sub(response, 1, 300) .. "\n\n" ..
                   "The response appears to be malformed or truncated JSON.\n" ..
                   "Please try again or use alternative ASK features."
    end
    
    -- Check for Shodan API errors
    if data.error then
        local error_msg = tostring(data.error)
        local full_error = "Shodan API Error: " .. error_msg
        
        -- Provide helpful information for membership errors
        if string.find(error_msg, "membership") or 
           string.find(error_msg, "Membership") or
           string.find(error_msg, "requires") or
           string.find(error_msg, "401") or
           string.find(error_msg, "Unauthorized") then
            full_error = full_error .. "\n\n" ..
                        "The Shodan host lookup endpoint requires a paid membership.\n" ..
                        "Free tier accounts cannot access IP host information.\n\n" ..
                        "Options:\n" ..
                        "1. Upgrade to Shodan Membership ($49 one-time) at: https://account.shodan.io/billing\n" ..
                        "2. Use Shodan's free InternetDB API for basic IP info: https://internetdb.shodan.io/\n" ..
                        "3. Use other ASK features (AbuseIPDB, VirusTotal, RDAP) which are free"
        end
        
        return nil, full_error
    end
    
    -- Check for other error indicators in Shodan response
    -- If we have a title but no IP data, it's likely an error page
    if data.title and (not data.ip_str and not data.ip and not data.org) then
        -- Shodan sometimes returns error pages with "title" field
        local error_msg = data.title
        if data.message then
            error_msg = data.message
        elseif data.error then
            error_msg = data.error
        end
        
        -- Check if this is a membership/authentication error
        local title_lower = string.lower(tostring(data.title or ""))
        local msg_lower = string.lower(tostring(error_msg or ""))
        
        if string.find(title_lower, "unauthorized") or 
           string.find(title_lower, "401") or
           string.find(title_lower, "forbidden") or
           string.find(title_lower, "403") or
           string.find(msg_lower, "membership") or
           string.find(msg_lower, "unauthorized") or
           string.find(msg_lower, "401") then
            return nil, "Shodan API Error: Unauthorized - Membership Required\n\n" ..
                       "The Shodan host lookup endpoint requires a paid membership.\n" ..
                       "Free tier accounts cannot access IP host information.\n\n" ..
                       "Options:\n" ..
                       "1. Upgrade to Shodan Membership ($49 one-time) at: https://account.shodan.io/billing\n" ..
                       "2. Use Shodan's free InternetDB API for basic IP info: https://internetdb.shodan.io/\n" ..
                       "3. Use other ASK features (AbuseIPDB, VirusTotal, RDAP) which are free"
        end
        
        -- Generic error with title
        return nil, "Shodan API Error: " .. tostring(error_msg) .. "\n\n" ..
                   "This might indicate:\n" ..
                   "- Invalid or missing API key\n" ..
                   "- Membership required (host lookup needs $49+ membership)\n" ..
                   "- Rate limiting or access restrictions\n\n" ..
                   "Check your API key at: https://account.shodan.io/"
    end
    
    -- Cache the result
    cache_set("shodan", ip, data)
    
    return data, nil
end

local function format_shodan_result(data)
    if not data then return "No data available" end
    
    local result = "=== IP Intelligence (Shodan) ===\n\n"
    result = result .. "ASK Build: " .. ASK_BUILD .. "\n\n"
    
    if data.ip_str then
        result = result .. "IP Address: " .. data.ip_str .. "\n"
    end
    
    if data.org then
        result = result .. "Organization: " .. data.org .. "\n"
    end
    
    if data.isp then
        result = result .. "ISP: " .. data.isp .. "\n"
    end
    
    if data.asn then
        result = result .. "ASN: " .. tostring(data.asn) .. "\n"
    end
    
    if data.hostnames then
        result = result .. "\n--- Hostnames ---\n"
        for i, hostname in ipairs(data.hostnames) do
            result = result .. hostname .. "\n"
        end
    end
    
    if data.location then
        result = result .. "\n--- Location ---\n"
        if data.location.city then
            result = result .. "City: " .. data.location.city .. "\n"
        end
        if data.location.region_code then
            result = result .. "Region: " .. data.location.region_code .. "\n"
        end
        if data.location.country_name then
            result = result .. "Country: " .. data.location.country_name .. "\n"
        end
        if data.location.latitude and data.location.longitude then
            result = result .. "Coordinates: " .. data.location.latitude .. ", " .. data.location.longitude .. "\n"
        end
    end
    
    if data.ports then
        result = result .. "\n--- Open Ports ---\n"
        for i, port in ipairs(data.ports) do
            result = result .. tostring(port) .. " "
            if i % 10 == 0 then result = result .. "\n" end
        end
        result = result .. "\n"
    end
    
    if data.data then
        result = result .. "\n--- Services ---\n"
        local count = 0
        for i, service in ipairs(data.data) do
            if count < 10 then -- Limit to first 10 services
                result = result .. "\nPort " .. tostring(service.port) .. " (" .. (service.transport or "tcp") .. ")\n"
                if service.product then
                    result = result .. "Product: " .. service.product .. "\n"
                end
                if service.version then
                    result = result .. "Version: " .. service.version .. "\n"
                end
                if service.banner then
                    local banner = service.banner
                    if string.len(banner) > 200 then
                        banner = string.sub(banner, 1, 200) .. "..."
                    end
                    result = result .. "Banner: " .. banner .. "\n"
                end
                count = count + 1
            end
        end
        if #data.data > 10 then
            result = result .. "\n... and " .. (#data.data - 10) .. " more services\n"
        end
    end
    
    if data.vulns then
        result = result .. "\n--- Vulnerabilities ---\n"
        local vuln_count = 0
        for vuln, info in pairs(data.vulns) do
            if vuln_count < 5 then
                result = result .. vuln .. "\n"
                vuln_count = vuln_count + 1
            end
        end
        if vuln_count >= 5 then
            result = result .. "... and more vulnerabilities\n"
        end
    end
    
    if data.last_update then
        result = result .. "\nLast Update: " .. data.last_update .. "\n"
    end
    
    return result
end

local function shodan_ip_callback(fieldname, ...)
    local fields = {...}
    local ip_raw = get_field_value(fieldname, "display", fields)
    
    if not ip_raw then
        show_error_window("Shodan IP Lookup", "Could not extract IP address from packet")
        return
    end
    
    -- Extract IP address from the field value (might contain hostname)
    local ip = extract_ip_from_string(ip_raw)
    if not ip then
        show_error_window("Shodan IP Lookup", "Could not extract valid IP address from: " .. ip_raw)
        return
    end
    
    -- Check if this is an RFC 1918 private address
    if is_rfc1918_private(ip) then
        local formatted = format_rfc1918_info(ip)
        show_result_window("Private IP Address: " .. ip, formatted)
        return
    end
    
    local data, err = lookup_shodan_ip(ip)
    if err then
        show_error_window("Shodan Error", "Error querying Shodan:\n" .. err)
        return
    end
    
    local formatted = format_shodan_result(data)
    show_result_window_with_buttons("Shodan IP: " .. ip, formatted, "Shodan", ip)
end

-------------------------------------------------
-- IPinfo Module
-------------------------------------------------

local function lookup_ipinfo_ip(ip)
    if not CONFIG.IPINFO_ENABLED or CONFIG.IPINFO_API_KEY == "" then
        return nil, "IPinfo API key not configured.\n\n" ..
                    "Option 1: Create file ~/.ask/IPINFO_API_KEY.txt with your API key\n" ..
                    "Option 2: Set environment variable: export IPINFO_API_KEY=\"your_key\"\n" ..
                    "Option 3: Launch Wireshark from terminal with env var set\n\n" ..
                    "Get free API key at: https://ipinfo.io/signup\n" ..
                    "Free tier: 50,000 requests/month (Lite API)\n" ..
                    "Paid tiers provide VPN/Proxy/Tor detection and more security features"
    end
    
    if not is_valid_ip(ip) then
        return nil, "Invalid IP address"
    end
    
    -- Check if this is an RFC 1918 private address
    if is_rfc1918_private(ip) then
        return nil, "IPinfo cannot provide information about private (RFC 1918) addresses.\n\n" ..
                   "Private addresses are not routable on the public Internet."
    end
    
    -- Check cache first
    local cached = cache_get("ipinfo", ip)
    if cached then
        log_message("Using cached IPinfo data for IP: " .. ip)
        return cached, nil
    end
    
    -- Build API URL
    -- IPinfo API: https://ipinfo.io/{ip}?token={token}
    local api_key = string.gsub(CONFIG.IPINFO_API_KEY, "%s+", "") -- Trim whitespace
    local url = string.format("https://ipinfo.io/%s?token=%s", url_encode(ip), url_encode(api_key))
    
    log_message("Querying IPinfo for IP: " .. ip)
    
    local response, err = http_get(url, {
        ["Accept"] = "application/json"
    })
    
    if err then
        return nil, "Error querying IPinfo: " .. err
    end
    
    if not response or response == "" then
        return nil, "IPinfo API returned empty response"
    end
    
    local data = parse_json(response)
    if not data then
        return nil, "Failed to parse IPinfo API response"
    end
    
    -- Cache the result
    cache_set("ipinfo", ip, data)
    
    return data, nil
end

local function format_ipinfo_result(data, ip)
    if not data then
        return "=== IPinfo IP Intelligence ===\n\nNo data available for: " .. ip
    end
    
    local result = "=== IPinfo IP Intelligence ===\n\n"
    result = result .. "IP Address: " .. (data.ip or ip) .. "\n\n"
    
    -- Hostname
    if data.hostname then
        result = result .. "--- Hostname ---\n"
        result = result .. "Hostname: " .. data.hostname .. "\n\n"
    end
    
    -- Geolocation Information
    if data.geo then
        result = result .. "--- Geolocation ---\n"
        if data.geo.city then result = result .. "City: " .. data.geo.city .. "\n" end
        if data.geo.region then result = result .. "Region: " .. data.geo.region .. "\n" end
        if data.geo.region_code then result = result .. "Region Code: " .. data.geo.region_code .. "\n" end
        if data.geo.country then result = result .. "Country: " .. data.geo.country .. "\n" end
        if data.geo.country_code then result = result .. "Country Code: " .. data.geo.country_code .. "\n" end
        if data.geo.continent then result = result .. "Continent: " .. data.geo.continent .. "\n" end
        if data.geo.continent_code then result = result .. "Continent Code: " .. data.geo.continent_code .. "\n" end
        if data.geo.latitude and data.geo.longitude then
            result = result .. "Coordinates: " .. data.geo.latitude .. ", " .. data.geo.longitude .. "\n"
        end
        if data.geo.timezone then result = result .. "Timezone: " .. data.geo.timezone .. "\n" end
        if data.geo.postal_code then result = result .. "Postal Code: " .. data.geo.postal_code .. "\n" end
        result = result .. "\n"
    elseif data.city or data.region or data.country then
        -- Legacy format support
        result = result .. "--- Geolocation ---\n"
        if data.city then result = result .. "City: " .. data.city .. "\n" end
        if data.region then result = result .. "Region: " .. data.region .. "\n" end
        if data.country then result = result .. "Country: " .. data.country .. "\n" end
        if data.loc then
            local lat, lon = string.match(data.loc, "([^,]+),([^,]+)")
            if lat and lon then
                result = result .. "Coordinates: " .. lat .. ", " .. lon .. "\n"
            end
        end
        if data.timezone then result = result .. "Timezone: " .. data.timezone .. "\n" end
        if data.postal then result = result .. "Postal Code: " .. data.postal .. "\n" end
        result = result .. "\n"
    end
    
    -- ASN Information
    if data.as then
        result = result .. "--- Autonomous System (ASN) ---\n"
        if data.as.asn then result = result .. "ASN: " .. data.as.asn .. "\n" end
        if data.as.name then result = result .. "AS Name: " .. data.as.name .. "\n" end
        if data.as.domain then result = result .. "AS Domain: " .. data.as.domain .. "\n" end
        if data.as.type then result = result .. "AS Type: " .. data.as.type .. "\n" end
        result = result .. "\n"
    elseif data.org then
        -- Legacy format support
        result = result .. "--- Autonomous System (ASN) ---\n"
        result = result .. "Organization: " .. data.org .. "\n\n"
    end
    
    -- Security: Privacy Detection (VPN/Proxy/Tor/Relay)
    if data.anonymous then
        result = result .. "--- Privacy & Security Detection ---\n"
        local privacy_flags = {}
        
        if data.anonymous.is_vpn == true then
            table.insert(privacy_flags, "VPN")
            if data.anonymous.name then
                result = result .. "⚠ VPN Detected: " .. data.anonymous.name .. "\n"
            else
                result = result .. "⚠ VPN Detected\n"
            end
        end
        
        if data.anonymous.is_proxy == true then
            table.insert(privacy_flags, "Proxy")
            result = result .. "⚠ Proxy Detected\n"
        end
        
        if data.anonymous.is_tor == true then
            table.insert(privacy_flags, "Tor")
            result = result .. "⚠ Tor Exit Node Detected\n"
        end
        
        if data.anonymous.is_relay == true then
            table.insert(privacy_flags, "Relay")
            result = result .. "⚠ Anonymous Relay Detected (e.g., iCloud Private Relay)\n"
        end
        
        if data.anonymous.is_anonymous == true then
            result = result .. "⚠ Anonymous IP Address\n"
        end
        
        if #privacy_flags == 0 then
            result = result .. "✓ No privacy services detected\n"
        end
        result = result .. "\n"
    end
    
    -- Security: Network Characteristics
    result = result .. "--- Network Characteristics ---\n"
    local network_flags = {}
    
    if data.is_hosting == true then
        table.insert(network_flags, "Hosting")
        result = result .. "⚠ Hosting/Datacenter IP\n"
    elseif data.is_hosting == false then
        result = result .. "✓ Not a hosting IP\n"
    end
    
    if data.is_mobile == true then
        table.insert(network_flags, "Mobile")
        result = result .. "📱 Mobile Network IP\n"
    end
    
    if data.is_satellite == true then
        table.insert(network_flags, "Satellite")
        result = result .. "🛰️ Satellite Internet IP\n"
    end
    
    if data.is_anycast == true then
        table.insert(network_flags, "Anycast")
        result = result .. "🌐 Anycast IP (maps to multiple servers)\n"
    end
    
    -- Mobile carrier information
    if data.mobile then
        result = result .. "\n--- Mobile Carrier ---\n"
        if data.mobile.name then result = result .. "Carrier: " .. data.mobile.name .. "\n" end
        if data.mobile.mcc then result = result .. "MCC: " .. data.mobile.mcc .. "\n" end
        if data.mobile.mnc then result = result .. "MNC: " .. data.mobile.mnc .. "\n" end
    end
    
    result = result .. "\n"
    
    -- Security Analysis
    result = result .. "--- Security Analysis ---\n"
    local security_notes = {}
    
    if data.anonymous and data.anonymous.is_vpn == true then
        table.insert(security_notes, "• VPN usage may indicate privacy-conscious user or potential evasion")
    end
    
    if data.anonymous and data.anonymous.is_proxy == true then
        table.insert(security_notes, "• Proxy detected - may be used for anonymity or malicious purposes")
    end
    
    if data.anonymous and data.anonymous.is_tor == true then
        table.insert(security_notes, "• Tor exit node - high anonymity, legitimate use but also used by threat actors")
    end
    
    if data.is_hosting == true then
        table.insert(security_notes, "• Hosting IP - likely a server/datacenter, not residential")
    end
    
    if data.as and data.as.type == "hosting" then
        table.insert(security_notes, "• ASN type indicates hosting provider - common for servers and cloud services")
    end
    
    if #security_notes > 0 then
        for _, note in ipairs(security_notes) do
            result = result .. note .. "\n"
        end
    else
        result = result .. "• No significant security indicators detected\n"
    end
    
    result = result .. "\n"
    result = result .. "--- Data Source ---\n"
    result = result .. "Provider: IPinfo.io\n"
    result = result .. "API: https://ipinfo.io/\n"
    result = result .. "Note: Privacy detection features require IPinfo Core/Plus/Business plan\n"
    
    return result
end

local function ipinfo_ip_callback(fieldname, ...)
    local fields = {...}
    local ip_raw = get_field_value(fieldname, "display", fields)
    
    if not ip_raw then
        show_error_window("IPinfo IP Lookup", "Could not extract IP address from packet")
        return
    end
    
    -- Extract IP address from the field value (might contain hostname)
    local ip = extract_ip_from_string(ip_raw)
    if not ip then
        show_error_window("IPinfo IP Lookup", "Could not extract valid IP address from: " .. ip_raw)
        return
    end
    
    -- Check if this is an RFC 1918 private address
    if is_rfc1918_private(ip) then
        local formatted = format_rfc1918_info(ip)
        show_result_window("Private IP Address: " .. ip, formatted)
        return
    end
    
    local data, err = lookup_ipinfo_ip(ip)
    if err then
        show_error_window("IPinfo Error", "Error querying IPinfo:\n" .. err)
        return
    end
    
    local formatted = format_ipinfo_result(data, ip)
    show_result_window_with_buttons("IPinfo IP Intelligence: " .. ip, formatted, "IPinfo", ip)
end

-------------------------------------------------
-- GreyNoise IP Intelligence Module
-------------------------------------------------

local function lookup_greynoise_ip(ip)
    if not CONFIG.GREYNOISE_ENABLED then
        return nil, "GreyNoise is disabled in configuration"
    end
    
    if not is_valid_ip(ip) then
        return nil, "Invalid IP address"
    end
    
    -- Check cache first
    local cached = cache_get("greynoise", ip)
    if cached then
        log_message("Using cached GreyNoise data for IP: " .. ip)
        return cached, nil
    end
    
    -- GreyNoise Community API endpoint
    local url = string.format("%s/ip/%s", CONFIG.GREYNOISE_API_URL, ip)
    
    log_message("Querying GreyNoise Community API for IP: " .. ip)
    
    -- GreyNoise Community API doesn't require authentication
    local headers = {
        ["Accept"] = "application/json",
        ["User-Agent"] = "ASK-Wireshark-Plugin/0.2.5"
    }
    
    local response, err = http_get(url, headers)
    if err then
        return nil, err
    end
    
    if not response or response == "" then
        return nil, "GreyNoise API returned empty response"
    end
    
    local data = parse_json(response)
    if not data then
        return nil, "Failed to parse GreyNoise response. Raw response: " .. string.sub(response, 1, 200)
    end
    
    -- Check if data is empty or all fields are nil (might indicate parsing issue)
    if not data or (not data.noise and not data.riot and not data.classification and not data.message and not data.ip) then
        log_message("GreyNoise: Warning - parsed data appears empty or malformed")
        -- Try to return a helpful message
        return {ip = ip, noise = false, riot = false, message = "IP not observed scanning the internet or contained in RIOT data set."}, nil
    end
    
    -- Check for rate limit errors (429)
    if data.message and (string.find(tostring(data.message), "rate limit") or 
                         string.find(tostring(data.message), "429") or
                         string.find(tostring(data.message), "rate-limit")) then
        local error_msg = "GreyNoise API Rate Limit: " .. tostring(data.message)
        error_msg = error_msg .. "\n\nGreyNoise Community API limit: 50 searches per week.\n" ..
                   "You've reached the free tier limit. Wait until next week or upgrade to a paid plan."
        return nil, error_msg
    end
    
    -- Check for authentication errors (401)
    if data.message and string.find(tostring(data.message), "Authentication") then
        return nil, "GreyNoise API Authentication Error: " .. tostring(data.message)
    end
    
    -- Check for invalid request errors (400)
    if data.message and string.find(tostring(data.message), "not a valid") then
        return nil, "GreyNoise API Error: " .. tostring(data.message)
    end
    
    -- Note: 404 responses are valid - they mean "IP not found" but still return data structure
    -- with noise=false, riot=false, and a message. We'll handle this in the formatter.
    
    -- Cache the result (GreyNoise data doesn't change frequently)
    cache_set("greynoise", ip, data)
    
    return data, nil
end

local function format_greynoise_result(data, ip)
    ip = ip or "unknown"
    
    if not data then
        return "=== GreyNoise IP Intelligence ===\n\n" ..
               "Query: " .. ip .. "\n\n" ..
               "No data available from GreyNoise for this IP address.\n" ..
               "This could mean:\n" ..
               "- The IP has not been observed scanning the internet\n" ..
               "- The IP is not in GreyNoise's database\n" ..
               "- The IP is legitimate and not part of the RIOT dataset"
    end
    
    local result = "=== GreyNoise IP Intelligence ===\n\n"
    result = result .. "Query: " .. ip .. "\n\n"
    
    -- Handle case where all fields are nil (parsing issue or empty response)
    if not data.noise and not data.riot and not data.classification and not data.message and not data.ip then
        result = result .. "--- Status ---\n"
        result = result .. "IP Not Found in GreyNoise Database\n\n"
        result = result .. "This means:\n"
        result = result .. "✓ The IP has NOT been observed scanning the internet (last 90 days)\n"
        result = result .. "✓ The IP is NOT in the RIOT dataset (legitimate services)\n"
        result = result .. "✓ This is generally a GOOD sign - no malicious scanning activity detected\n\n"
        result = result .. "However, this does NOT mean the IP is safe:\n"
        result = result .. "- GreyNoise only tracks internet-wide scanning activity\n"
        result = result .. "- Targeted attacks may not be detected\n"
        result = result .. "- The IP may be new or inactive\n"
        result = result .. "- Always use multiple threat intelligence sources\n"
        result = result .. "\n--- Additional Information ---\n"
        result = result .. "View full details: https://www.greynoise.io/viz/ip/" .. ip .. "\n"
        return result
    end
    
    -- Check if IP was not found (404 response - still valid JSON but no data)
    -- GreyNoise returns noise=false, riot=false, and a message when IP not found
    local is_not_found = false
    if data.message then
        local msg_lower = string.lower(tostring(data.message))
        if string.find(msg_lower, "not observed") or 
           string.find(msg_lower, "not contained") or
           string.find(msg_lower, "not found") then
            is_not_found = true
        end
    end
    
    -- Also check if noise=false, riot=false, and no classification (typical "not found" pattern)
    -- Check both nil and empty string for classification
    -- Use explicit boolean comparison to handle Lua truthiness
    local noise_val = data.noise
    local riot_val = data.riot
    local classification_val = data.classification
    
    local has_classification = classification_val and classification_val ~= "" and classification_val ~= "unknown"
    
    -- Check if noise is explicitly false (not nil, not true)
    local noise_is_false = (noise_val == false)
    local riot_is_false = (riot_val == false)
    
    -- Also check if all values are nil (empty response) - this indicates IP not found
    if not is_not_found and ((noise_is_false and riot_is_false and not has_classification) or 
       (not noise_val and not riot_val and not classification_val)) then
        is_not_found = true
    end
    
    if is_not_found then
        result = result .. "--- Status ---\n"
        result = result .. "IP Not Found in GreyNoise Database\n\n"
        result = result .. "This means:\n"
        result = result .. "✓ The IP has NOT been observed scanning the internet (last 90 days)\n"
        result = result .. "✓ The IP is NOT in the RIOT dataset (legitimate services)\n"
        result = result .. "✓ This is generally a GOOD sign - no malicious scanning activity detected\n\n"
        result = result .. "However, this does NOT mean the IP is safe:\n"
        result = result .. "- GreyNoise only tracks internet-wide scanning activity\n"
        result = result .. "- Targeted attacks may not be detected\n"
        result = result .. "- The IP may be new or inactive\n"
        result = result .. "- Always use multiple threat intelligence sources\n"
        result = result .. "\n--- Additional Information ---\n"
        if data.link then
            result = result .. "View full details: " .. data.link .. "\n"
        else
            result = result .. "View full details: https://www.greynoise.io/viz/ip/" .. ip .. "\n"
        end
        return result
    end
    
    -- IP address
    if data.ip then
        result = result .. "IP Address: " .. data.ip .. "\n"
    end
    
    -- Classification
    if data.classification then
        result = result .. "\n--- Classification ---\n"
        result = result .. "Status: " .. data.classification .. "\n"
        
        if data.classification == "malicious" then
            result = result .. "⚠ WARNING: This IP is classified as MALICIOUS\n"
        elseif data.classification == "benign" then
            result = result .. "✓ This IP is classified as BENIGN\n"
        elseif data.classification == "unknown" then
            result = result .. "? This IP classification is UNKNOWN\n"
        end
    end
    
    -- Noise detection
    if data.noise ~= nil then
        result = result .. "\n--- Internet Scanning Activity ---\n"
        if data.noise then
            result = result .. "Internet Scanner: YES ⚠\n"
            result = result .. "This IP has been observed scanning the internet in the last 90 days\n"
            result = result .. "This indicates automated scanning/probing activity\n"
            result = result .. "This is suspicious behavior and should be investigated\n"
        else
            result = result .. "Internet Scanner: NO ✓\n"
            result = result .. "This IP has NOT been observed scanning the internet\n"
            result = result .. "This is a positive indicator (no mass scanning detected)\n"
        end
    end
    
    -- RIOT dataset (legitimate services)
    if data.riot ~= nil then
        result = result .. "\n--- RIOT Dataset (Legitimate Services) ---\n"
        if data.riot then
            result = result .. "RIOT Service: YES ✓\n"
            result = result .. "This IP belongs to a legitimate business service\n"
            if data.name and data.name ~= "unknown" then
                result = result .. "Service Name: " .. data.name .. "\n"
            end
            if data.category then
                result = result .. "Category: " .. data.category .. "\n"
            end
            result = result .. "This IP is likely safe to communicate with\n"
        else
            result = result .. "RIOT Service: NO\n"
            result = result .. "This IP is not in the RIOT (legitimate services) dataset\n"
        end
    end
    
    -- Organization (only show if not already shown in RIOT section)
    if data.name and data.name ~= "unknown" and not data.riot then
        result = result .. "\n--- Organization ---\n"
        result = result .. "Name: " .. data.name .. "\n"
    end
    
    -- Last seen
    if data.last_seen then
        result = result .. "\n--- Activity Timeline ---\n"
        result = result .. "Last Seen: " .. data.last_seen .. "\n"
    end
    
    -- Link to GreyNoise
    result = result .. "\n--- Additional Information ---\n"
    if data.link then
        result = result .. "View full details: " .. data.link .. "\n"
    else
        result = result .. "View full details: https://www.greynoise.io/viz/ip/" .. ip .. "\n"
    end
    result = result .. "\nNote: GreyNoise Community API provides basic classification.\n"
    result = result .. "For detailed threat intelligence, consider upgrading to a paid plan.\n"
    
    return result
end

local function greynoise_ip_callback(fieldname, ...)
    local fields = {...}
    local ip_raw = get_field_value(fieldname, "display", fields)
    
    if not ip_raw then
        show_error_window("GreyNoise IP Lookup", "Could not extract IP address from packet")
        return
    end
    
    -- Extract IP address from the field value (might contain hostname)
    local ip = extract_ip_from_string(ip_raw)
    if not ip then
        show_error_window("GreyNoise IP Lookup", "Could not extract valid IP address from: " .. ip_raw)
        return
    end
    
    -- Check if this is an RFC 1918 private address
    if is_rfc1918_private(ip) then
        local formatted = format_rfc1918_info(ip)
        show_result_window("Private IP Address: " .. ip, formatted)
        return
    end
    
    local data, err = lookup_greynoise_ip(ip)
    if err then
        show_error_window("GreyNoise Error", "Error querying GreyNoise:\n" .. err)
        return
    end
    
    local formatted = format_greynoise_result(data, ip)
    show_result_window("GreyNoise IP Intelligence: " .. ip, formatted)
end

-------------------------------------------------
--- AlienVault OTX (Open Threat Exchange) Module
-------------------------------------------------

-- Lookup IP address in OTX
local function lookup_otx_ip(ip)
    if not CONFIG.OTX_ENABLED then
        return nil, "OTX is disabled in configuration"
    end
    
    if not CONFIG.OTX_API_KEY or CONFIG.OTX_API_KEY == "" then
        return nil, "OTX API key not configured. Please set OTX_API_KEY environment variable or create ~/.ask/OTX_API_KEY.txt"
    end
    
    if not is_valid_ip(ip) then
        return nil, "Invalid IP address"
    end
    
    -- Check cache first
    local cached = cache_get("otx_ip", ip)
    if cached then
        log_message("Using cached OTX data for IP: " .. ip)
        return cached, nil
    end
    
    -- Determine IP version for endpoint
    local ip_type = is_valid_ipv6(ip) and "IPv6" or "IPv4"
    local url = string.format("%s/indicators/%s/%s/general", CONFIG.OTX_API_URL, ip_type, ip)
    
    log_message("Querying OTX API for IP: " .. ip)
    
    local headers = {
        ["Accept"] = "application/json",
        ["X-OTX-API-KEY"] = CONFIG.OTX_API_KEY,
        ["User-Agent"] = "ASK-Wireshark-Plugin/0.2.5"
    }
    
    local response, err = http_get(url, headers)
    if err then
        return nil, err
    end
    
    if not response or response == "" then
        return nil, "OTX API returned empty response"
    end
    
    local data = parse_json(response)
    if not data then
        return nil, "Failed to parse OTX response. Raw response: " .. string.sub(response, 1, 200)
    end
    
    -- Check for API errors
    if data.error then
        return nil, "OTX API Error: " .. tostring(data.error)
    end
    
    -- Cache the result
    cache_set("otx_ip", ip, data, CONFIG.CACHE_TTL_REPUTATION)
    
    return data, nil
end

-- Lookup domain in OTX
local function lookup_otx_domain(domain)
    if not CONFIG.OTX_ENABLED then
        return nil, "OTX is disabled in configuration"
    end
    
    if not CONFIG.OTX_API_KEY or CONFIG.OTX_API_KEY == "" then
        return nil, "OTX API key not configured. Please set OTX_API_KEY environment variable or create ~/.ask/OTX_API_KEY.txt"
    end
    
    if not domain or domain == "" then
        return nil, "Invalid domain"
    end
    
    -- Check cache first
    local cached = cache_get("otx_domain", domain)
    if cached then
        log_message("Using cached OTX data for domain: " .. domain)
        return cached, nil
    end
    
    local url = string.format("%s/indicators/domain/%s/general", CONFIG.OTX_API_URL, url_encode(domain))
    
    log_message("Querying OTX API for domain: " .. domain)
    
    local headers = {
        ["Accept"] = "application/json",
        ["X-OTX-API-KEY"] = CONFIG.OTX_API_KEY,
        ["User-Agent"] = "ASK-Wireshark-Plugin/0.2.5"
    }
    
    local response, err = http_get(url, headers)
    if err then
        return nil, err
    end
    
    if not response or response == "" then
        return nil, "OTX API returned empty response"
    end
    
    local data = parse_json(response)
    if not data then
        return nil, "Failed to parse OTX response. Raw response: " .. string.sub(response, 1, 200)
    end
    
    -- Check for API errors
    if data.error then
        return nil, "OTX API Error: " .. tostring(data.error)
    end
    
    -- Cache the result
    cache_set("otx_domain", domain, data, CONFIG.CACHE_TTL_REPUTATION)
    
    return data, nil
end

-- Lookup URL in OTX
local function lookup_otx_url(url)
    if not CONFIG.OTX_ENABLED then
        return nil, "OTX is disabled in configuration"
    end
    
    if not CONFIG.OTX_API_KEY or CONFIG.OTX_API_KEY == "" then
        return nil, "OTX API key not configured. Please set OTX_API_KEY environment variable or create ~/.ask/OTX_API_KEY.txt"
    end
    
    if not url or url == "" then
        return nil, "Invalid URL"
    end
    
    -- Check cache first
    local cached = cache_get("otx_url", url)
    if cached then
        log_message("Using cached OTX data for URL: " .. url)
        return cached, nil
    end
    
    -- OTX requires URL encoding for the URL parameter
    local encoded_url = url_encode(url)
    local api_url = string.format("%s/indicators/url/%s/general", CONFIG.OTX_API_URL, encoded_url)
    
    log_message("Querying OTX API for URL: " .. url)
    
    local headers = {
        ["Accept"] = "application/json",
        ["X-OTX-API-KEY"] = CONFIG.OTX_API_KEY,
        ["User-Agent"] = "ASK-Wireshark-Plugin/0.2.5"
    }
    
    local response, err = http_get(api_url, headers)
    if err then
        return nil, err
    end
    
    if not response or response == "" then
        return nil, "OTX API returned empty response"
    end
    
    local data = parse_json(response)
    if not data then
        return nil, "Failed to parse OTX response. Raw response: " .. string.sub(response, 1, 200)
    end
    
    -- Check for API errors
    if data.error then
        return nil, "OTX API Error: " .. tostring(data.error)
    end
    
    -- Cache the result
    cache_set("otx_url", url, data, CONFIG.CACHE_TTL_REPUTATION)
    
    return data, nil
end

-- Format OTX IP result
local function format_otx_ip_result(data, ip)
    ip = ip or "unknown"
    
    if not data then
        return "=== AlienVault OTX IP Intelligence ===\n\n" ..
               "Query: " .. ip .. "\n\n" ..
               "No data available from OTX for this IP address.\n" ..
               "This could mean:\n" ..
               "- The IP has not been observed in any threat intelligence reports\n" ..
               "- The IP is not in OTX's database\n" ..
               "- The IP is clean and has no associated threats"
    end
    
    local result = "=== AlienVault OTX IP Intelligence ===\n\n"
    result = result .. "Query: " .. ip .. "\n\n"
    
    -- Indicator type
    if data.type then
        result = result .. "--- Indicator Type ---\n"
        result = result .. "Type: " .. tostring(data.type) .. "\n\n"
    end
    
    -- Reputation score (0-100, higher is more suspicious)
    if data.reputation then
        result = result .. "--- Reputation Score ---\n"
        local rep = tonumber(data.reputation) or 0
        result = result .. "Score: " .. rep .. "/100\n"
        if rep >= 75 then
            result = result .. "Status: HIGH RISK - Strong indicators of malicious activity\n"
        elseif rep >= 50 then
            result = result .. "Status: MODERATE RISK - Some suspicious indicators\n"
        elseif rep >= 25 then
            result = result .. "Status: LOW RISK - Minor suspicious indicators\n"
        else
            result = result .. "Status: CLEAN - No significant threat indicators\n"
        end
        result = result .. "\n"
    end
    
    -- Pulse information (threat intelligence reports)
    if data.pulse_info then
        local pulse_count = data.pulse_info.count or 0
        if pulse_count > 0 then
            result = result .. "--- Threat Intelligence Reports (Pulses) ---\n"
            result = result .. "Total Pulses: " .. pulse_count .. "\n\n"
            
            if data.pulse_info.pulses and #data.pulse_info.pulses > 0 then
                result = result .. "Recent Threat Reports:\n"
                local pulse_limit = math.min(5, #data.pulse_info.pulses)  -- Show up to 5 pulses
                for i = 1, pulse_limit do
                    local pulse = data.pulse_info.pulses[i]
                    result = result .. "\n" .. i .. ". "
                    if pulse.name then
                        result = result .. pulse.name .. "\n"
                    end
                    if pulse.description then
                        result = result .. "   Description: " .. string.sub(pulse.description, 1, 100)
                        if string.len(pulse.description) > 100 then
                            result = result .. "..."
                        end
                        result = result .. "\n"
                    end
                    if pulse.author and pulse.author.username then
                        result = result .. "   Author: " .. pulse.author.username .. "\n"
                    end
                    if pulse.created then
                        result = result .. "   Created: " .. pulse.created .. "\n"
                    end
                    if pulse.TLP then
                        result = result .. "   TLP: " .. pulse.TLP .. "\n"
                    end
                    if pulse.tags and #pulse.tags > 0 then
                        result = result .. "   Tags: " .. table.concat(pulse.tags, ", ") .. "\n"
                    end
                end
                if pulse_count > pulse_limit then
                    result = result .. "\n... and " .. (pulse_count - pulse_limit) .. " more pulse(s)\n"
                end
                result = result .. "\n"
            end
        else
            result = result .. "--- Threat Intelligence Reports ---\n"
            result = result .. "No threat intelligence pulses found for this IP.\n\n"
        end
    end
    
    -- Geographic information
    if data.country_name or data.asn then
        result = result .. "--- Geographic Information ---\n"
        if data.country_name then
            result = result .. "Country: " .. data.country_name .. "\n"
        end
        if data.asn then
            result = result .. "ASN: " .. data.asn .. "\n"
        end
        if data.latitude and data.longitude then
            result = result .. "Coordinates: " .. data.latitude .. ", " .. data.longitude .. "\n"
        end
        result = result .. "\n"
    end
    
    -- Available sections
    if data.sections and #data.sections > 0 then
        result = result .. "--- Available Data Sections ---\n"
        result = result .. "Additional data available: " .. table.concat(data.sections, ", ") .. "\n"
        result = result .. "\n"
    end
    
    -- Link to OTX
    result = result .. "--- Additional Information ---\n"
    result = result .. "View full details: https://otx.alienvault.com/indicator/ip/" .. ip .. "\n"
    result = result .. "\nNote: OTX is a free, community-driven threat intelligence platform.\n"
    result = result .. "For more detailed analysis, visit the OTX website.\n"
    
    return result
end

-- Format OTX domain result
local function format_otx_domain_result(data, domain)
    domain = domain or "unknown"
    
    if not data then
        return "=== AlienVault OTX Domain Intelligence ===\n\n" ..
               "Query: " .. domain .. "\n\n" ..
               "No data available from OTX for this domain.\n" ..
               "This could mean:\n" ..
               "- The domain has not been observed in any threat intelligence reports\n" ..
               "- The domain is not in OTX's database\n" ..
               "- The domain is clean and has no associated threats"
    end
    
    local result = "=== AlienVault OTX Domain Intelligence ===\n\n"
    result = result .. "Query: " .. domain .. "\n\n"
    
    -- Pulse information (threat intelligence reports)
    if data.pulse_info then
        local pulse_count = data.pulse_info.count or 0
        if pulse_count > 0 then
            result = result .. "--- Threat Intelligence Reports (Pulses) ---\n"
            result = result .. "Total Pulses: " .. pulse_count .. "\n\n"
            
            if data.pulse_info.pulses and #data.pulse_info.pulses > 0 then
                result = result .. "Recent Threat Reports:\n"
                local pulse_limit = math.min(5, #data.pulse_info.pulses)  -- Show up to 5 pulses
                for i = 1, pulse_limit do
                    local pulse = data.pulse_info.pulses[i]
                    result = result .. "\n" .. i .. ". "
                    if pulse.name then
                        result = result .. pulse.name .. "\n"
                    end
                    if pulse.description then
                        result = result .. "   Description: " .. string.sub(pulse.description, 1, 100)
                        if string.len(pulse.description) > 100 then
                            result = result .. "..."
                        end
                        result = result .. "\n"
                    end
                    if pulse.author and pulse.author.username then
                        result = result .. "   Author: " .. pulse.author.username .. "\n"
                    end
                    if pulse.created then
                        result = result .. "   Created: " .. pulse.created .. "\n"
                    end
                    if pulse.TLP then
                        result = result .. "   TLP: " .. pulse.TLP .. "\n"
                    end
                    if pulse.tags and #pulse.tags > 0 then
                        result = result .. "   Tags: " .. table.concat(pulse.tags, ", ") .. "\n"
                    end
                end
                if pulse_count > pulse_limit then
                    result = result .. "\n... and " .. (pulse_count - pulse_limit) .. " more pulse(s)\n"
                end
                result = result .. "\n"
            end
        else
            result = result .. "--- Threat Intelligence Reports ---\n"
            result = result .. "No threat intelligence pulses found for this domain.\n\n"
        end
    end
    
    -- Available sections
    if data.sections and #data.sections > 0 then
        result = result .. "--- Available Data Sections ---\n"
        result = result .. "Additional data available: " .. table.concat(data.sections, ", ") .. "\n"
        result = result .. "\n"
    end
    
    -- Link to OTX
    result = result .. "--- Additional Information ---\n"
    result = result .. "View full details: https://otx.alienvault.com/indicator/domain/" .. url_encode(domain) .. "\n"
    result = result .. "\nNote: OTX is a free, community-driven threat intelligence platform.\n"
    result = result .. "For more detailed analysis, visit the OTX website.\n"
    
    return result
end

-- Format OTX URL result
local function format_otx_url_result(data, url)
    url = url or "unknown"
    
    if not data then
        return "=== AlienVault OTX URL Intelligence ===\n\n" ..
               "Query: " .. url .. "\n\n" ..
               "No data available from OTX for this URL.\n" ..
               "This could mean:\n" ..
               "- The URL has not been observed in any threat intelligence reports\n" ..
               "- The URL is not in OTX's database\n" ..
               "- The URL is clean and has no associated threats"
    end
    
    local result = "=== AlienVault OTX URL Intelligence ===\n\n"
    result = result .. "Query: " .. url .. "\n\n"
    
    -- Pulse information (threat intelligence reports)
    if data.pulse_info then
        local pulse_count = data.pulse_info.count or 0
        if pulse_count > 0 then
            result = result .. "--- Threat Intelligence Reports (Pulses) ---\n"
            result = result .. "Total Pulses: " .. pulse_count .. "\n\n"
            
            if data.pulse_info.pulses and #data.pulse_info.pulses > 0 then
                result = result .. "Recent Threat Reports:\n"
                local pulse_limit = math.min(5, #data.pulse_info.pulses)  -- Show up to 5 pulses
                for i = 1, pulse_limit do
                    local pulse = data.pulse_info.pulses[i]
                    result = result .. "\n" .. i .. ". "
                    if pulse.name then
                        result = result .. pulse.name .. "\n"
                    end
                    if pulse.description then
                        result = result .. "   Description: " .. string.sub(pulse.description, 1, 100)
                        if string.len(pulse.description) > 100 then
                            result = result .. "..."
                        end
                        result = result .. "\n"
                    end
                    if pulse.author and pulse.author.username then
                        result = result .. "   Author: " .. pulse.author.username .. "\n"
                    end
                    if pulse.created then
                        result = result .. "   Created: " .. pulse.created .. "\n"
                    end
                    if pulse.TLP then
                        result = result .. "   TLP: " .. pulse.TLP .. "\n"
                    end
                    if pulse.tags and #pulse.tags > 0 then
                        result = result .. "   Tags: " .. table.concat(pulse.tags, ", ") .. "\n"
                    end
                end
                if pulse_count > pulse_limit then
                    result = result .. "\n... and " .. (pulse_count - pulse_limit) .. " more pulse(s)\n"
                end
                result = result .. "\n"
            end
        else
            result = result .. "--- Threat Intelligence Reports ---\n"
            result = result .. "No threat intelligence pulses found for this URL.\n\n"
        end
    end
    
    -- Available sections
    if data.sections and #data.sections > 0 then
        result = result .. "--- Available Data Sections ---\n"
        result = result .. "Additional data available: " .. table.concat(data.sections, ", ") .. "\n"
        result = result .. "\n"
    end
    
    -- Link to OTX
    result = result .. "--- Additional Information ---\n"
    result = result .. "View full details: https://otx.alienvault.com/indicator/url/" .. url_encode(url) .. "\n"
    result = result .. "\nNote: OTX is a free, community-driven threat intelligence platform.\n"
    result = result .. "For more detailed analysis, visit the OTX website.\n"
    
    return result
end

-- OTX IP callback
local function otx_ip_callback(fieldname, ...)
    local fields = {...}
    local ip_raw = get_field_value(fieldname, "display", fields)
    
    if not ip_raw then
        show_error_window("OTX IP Lookup", "Could not extract IP address from packet")
        return
    end
    
    -- Extract IP address from the field value (might contain hostname)
    local ip = extract_ip_from_string(ip_raw)
    if not ip then
        show_error_window("OTX IP Lookup", "Could not extract valid IP address from: " .. ip_raw)
        return
    end
    
    -- Check if this is an RFC 1918 private address
    if is_rfc1918_private(ip) then
        local formatted = format_rfc1918_info(ip)
        show_result_window("Private IP Address: " .. ip, formatted)
        return
    end
    
    local data, err = lookup_otx_ip(ip)
    if err then
        show_error_window("OTX Error", "Error querying OTX:\n" .. err)
        return
    end
    
    local formatted = format_otx_ip_result(data, ip)
    show_result_window("AlienVault OTX IP Intelligence: " .. ip, formatted)
end

-- OTX domain callback
local function otx_domain_callback(...)
    local fields = {...}
    local domain = get_field_value("dns.qry.name", "display", fields)
    
    if not domain then
        show_error_window("OTX Domain Lookup", "Could not extract domain from packet")
        return
    end
    
    local data, err = lookup_otx_domain(domain)
    if err then
        show_error_window("OTX Error", "Error querying OTX:\n" .. err)
        return
    end
    
    local formatted = format_otx_domain_result(data, domain)
    show_result_window("AlienVault OTX Domain Intelligence: " .. domain, formatted)
end

-- OTX URL callback
local function otx_url_callback(...)
    local fields = {...}
    local url = get_field_value("http.request.full_uri", "display", fields)
    
    if not url then
        show_error_window("OTX URL Lookup", "Could not extract URL from packet")
        return
    end
    
    local data, err = lookup_otx_url(url)
    if err then
        show_error_window("OTX Error", "Error querying OTX:\n" .. err)
        return
    end
    
    local formatted = format_otx_url_result(data, url)
    show_result_window("AlienVault OTX URL Intelligence: " .. url, formatted)
end

-------------------------------------------------
--- Abuse.ch (URLhaus & ThreatFox) Module
-------------------------------------------------

-- Lookup URL in URLhaus
local function lookup_urlhaus_url(url)
    if not CONFIG.ABUSECH_ENABLED then
        return nil, "Abuse.ch is disabled in configuration"
    end
    
    if not CONFIG.ABUSECH_API_KEY or CONFIG.ABUSECH_API_KEY == "" then
        return nil, "Abuse.ch API key not configured. Please set ABUSECH_API_KEY environment variable or create ~/.ask/ABUSECH_API_KEY.txt"
    end
    
    if not url or url == "" then
        return nil, "Invalid URL"
    end
    
    -- Check cache first
    local cached = cache_get("urlhaus_url", url)
    if cached then
        log_message("Using cached URLhaus data for URL: " .. url)
        return cached, nil
    end
    
    local api_url = CONFIG.URLHAUS_API_URL .. "/url/"
    
    log_message("Querying URLhaus API for URL: " .. url)
    
    local headers = {
        ["Accept"] = "application/json",
        ["Auth-Key"] = CONFIG.ABUSECH_API_KEY,
        ["Content-Type"] = "application/x-www-form-urlencoded",
        ["User-Agent"] = "ASK-Wireshark-Plugin/0.2.5"
    }
    
    -- URLhaus requires POST with url parameter
    local post_data = "url=" .. url_encode(url)
    
    local response, err = http_post(api_url, headers, post_data)
    if err then
        return nil, err
    end
    
    if not response or response == "" then
        return nil, "URLhaus API returned empty response"
    end
    
    local data = parse_json(response)
    if not data then
        return nil, "Failed to parse URLhaus response. Raw response: " .. string.sub(response, 1, 200)
    end
    
    -- Check for API errors
    if data.query_status then
        if data.query_status == "no_results" then
            return {query_status = "no_results"}, nil
        elseif data.query_status ~= "ok" then
            return nil, "URLhaus API Error: " .. tostring(data.query_status)
        end
    end
    
    -- Cache the result
    cache_set("urlhaus_url", url, data, CONFIG.CACHE_TTL_REPUTATION)
    
    return data, nil
end

-- Lookup host (IP or domain) in URLhaus
local function lookup_urlhaus_host(host)
    if not CONFIG.ABUSECH_ENABLED then
        return nil, "Abuse.ch is disabled in configuration"
    end
    
    if not CONFIG.ABUSECH_API_KEY or CONFIG.ABUSECH_API_KEY == "" then
        return nil, "Abuse.ch API key not configured. Please set ABUSECH_API_KEY environment variable or create ~/.ask/ABUSECH_API_KEY.txt"
    end
    
    if not host or host == "" then
        return nil, "Invalid host"
    end
    
    -- Check cache first
    local cached = cache_get("urlhaus_host", host)
    if cached then
        log_message("Using cached URLhaus data for host: " .. host)
        return cached, nil
    end
    
    local api_url = CONFIG.URLHAUS_API_URL .. "/host/"
    
    log_message("Querying URLhaus API for host: " .. host)
    
    local headers = {
        ["Accept"] = "application/json",
        ["Auth-Key"] = CONFIG.ABUSECH_API_KEY,
        ["Content-Type"] = "application/x-www-form-urlencoded",
        ["User-Agent"] = "ASK-Wireshark-Plugin/0.2.5"
    }
    
    -- URLhaus requires POST with host parameter
    local post_data = "host=" .. url_encode(host)
    
    local response, err = http_post(api_url, headers, post_data)
    if err then
        return nil, err
    end
    
    if not response or response == "" then
        return nil, "URLhaus API returned empty response"
    end
    
    local data = parse_json(response)
    if not data then
        return nil, "Failed to parse URLhaus response. Raw response: " .. string.sub(response, 1, 200)
    end
    
    -- Check for API errors
    if data.query_status then
        if data.query_status == "no_results" then
            return {query_status = "no_results"}, nil
        elseif data.query_status ~= "ok" then
            return nil, "URLhaus API Error: " .. tostring(data.query_status)
        end
    end
    
    -- Cache the result
    cache_set("urlhaus_host", host, data, CONFIG.CACHE_TTL_REPUTATION)
    
    return data, nil
end

-- Search IOC in ThreatFox
local function lookup_threatfox_ioc(ioc)
    if not CONFIG.ABUSECH_ENABLED then
        return nil, "Abuse.ch is disabled in configuration"
    end
    
    if not CONFIG.ABUSECH_API_KEY or CONFIG.ABUSECH_API_KEY == "" then
        return nil, "Abuse.ch API key not configured. Please set ABUSECH_API_KEY environment variable or create ~/.ask/ABUSECH_API_KEY.txt"
    end
    
    if not ioc or ioc == "" then
        return nil, "Invalid IOC"
    end
    
    -- Check cache first
    local cached = cache_get("threatfox_ioc", ioc)
    if cached then
        log_message("Using cached ThreatFox data for IOC: " .. ioc)
        return cached, nil
    end
    
    local api_url = CONFIG.THREATFOX_API_URL .. "/"
    
    log_message("Querying ThreatFox API for IOC: " .. ioc)
    
    local headers = {
        ["Accept"] = "application/json",
        ["Auth-Key"] = CONFIG.ABUSECH_API_KEY,
        ["Content-Type"] = "application/json",
        ["User-Agent"] = "ASK-Wireshark-Plugin/0.2.5"
    }
    
    -- ThreatFox requires JSON POST body
    local json_body = string.format('{"query": "search_ioc", "search_term": "%s", "exact_match": true}', 
                                    string.gsub(ioc, '"', '\\"'))
    
    local response, err = http_post(api_url, headers, json_body)
    if err then
        return nil, err
    end
    
    if not response or response == "" then
        return nil, "ThreatFox API returned empty response"
    end
    
    local data = parse_json(response)
    if not data then
        return nil, "Failed to parse ThreatFox response. Raw response: " .. string.sub(response, 1, 200)
    end
    
    -- Check for API errors
    if data.query_status and data.query_status ~= "ok" then
        -- ThreatFox returns "no_result" (singular) when no results found
        if data.query_status == "no_results" or data.query_status == "no_result" then
            return {query_status = "no_results", data = {}}, nil
        else
            return nil, "ThreatFox API Error: " .. tostring(data.query_status)
        end
    end
    
    -- Cache the result
    cache_set("threatfox_ioc", ioc, data, CONFIG.CACHE_TTL_REPUTATION)
    
    return data, nil
end

-- Format URLhaus URL result
local function format_urlhaus_url_result(data, url)
    url = url or "unknown"
    
    if not data or data.query_status == "no_results" then
        return "=== URLhaus URL Intelligence ===\n\n" ..
               "Query: " .. url .. "\n\n" ..
               "No data available from URLhaus for this URL.\n" ..
               "This could mean:\n" ..
               "- The URL has not been observed distributing malware\n" ..
               "- The URL is not in URLhaus's database\n" ..
               "- The URL is clean and has no associated threats"
    end
    
    local result = "=== URLhaus URL Intelligence ===\n\n"
    result = result .. "Query: " .. url .. "\n\n"
    
    -- URL status
    if data.url_status then
        result = result .. "--- URL Status ---\n"
        result = result .. "Status: " .. data.url_status .. "\n"
        if data.url_status == "online" then
            result = result .. "⚠️ WARNING: URL is currently ONLINE and serving malware!\n"
        elseif data.url_status == "offline" then
            result = result .. "✓ URL is offline (no longer serving malware)\n"
            if data.last_online then
                result = result .. "Last Online: " .. data.last_online .. "\n"
            end
        end
        result = result .. "\n"
    end
    
    -- Threat type
    if data.threat then
        result = result .. "--- Threat Type ---\n"
        result = result .. "Type: " .. data.threat .. "\n\n"
    end
    
    -- Blacklists
    if data.blacklists then
        result = result .. "--- Blacklist Status ---\n"
        if data.blacklists.spamhaus_dbl and data.blacklists.spamhaus_dbl ~= "not listed" then
            result = result .. "Spamhaus DBL: " .. data.blacklists.spamhaus_dbl .. " ⚠️\n"
        end
        if data.blacklists.surbl and data.blacklists.surbl == "listed" then
            result = result .. "SURBL: Listed ⚠️\n"
        end
        if (not data.blacklists.spamhaus_dbl or data.blacklists.spamhaus_dbl == "not listed") and
           (not data.blacklists.surbl or data.blacklists.surbl == "not listed") then
            result = result .. "Not listed on major blacklists\n"
        end
        result = result .. "\n"
    end
    
    -- Tags
    if data.tags and #data.tags > 0 then
        result = result .. "--- Tags ---\n"
        result = result .. table.concat(data.tags, ", ") .. "\n\n"
    end
    
    -- Payloads
    if data.payloads and #data.payloads > 0 then
        result = result .. "--- Malware Payloads ---\n"
        result = result .. "Total Payloads: " .. #data.payloads .. "\n\n"
        local payload_limit = math.min(5, #data.payloads)
        for i = 1, payload_limit do
            local payload = data.payloads[i]
            result = result .. i .. ". "
            if payload.filename then
                result = result .. "Filename: " .. payload.filename .. "\n"
            end
            if payload.file_type then
                result = result .. "   Type: " .. payload.file_type .. "\n"
            end
            if payload.response_sha256 then
                result = result .. "   SHA256: " .. payload.response_sha256 .. "\n"
            end
            if payload.signature then
                result = result .. "   Malware Family: " .. payload.signature .. "\n"
            end
            if payload.firstseen then
                result = result .. "   First Seen: " .. payload.firstseen .. "\n"
            end
            result = result .. "\n"
        end
        if #data.payloads > payload_limit then
            result = result .. "... and " .. (#data.payloads - payload_limit) .. " more payload(s)\n\n"
        end
    end
    
    -- Date added
    if data.date_added then
        result = result .. "--- Timeline ---\n"
        result = result .. "Date Added: " .. data.date_added .. "\n\n"
    end
    
    -- Link to URLhaus
    if data.urlhaus_reference then
        result = result .. "--- Additional Information ---\n"
        result = result .. "View full details: " .. data.urlhaus_reference .. "\n"
    else
        result = result .. "--- Additional Information ---\n"
        result = result .. "View full details: https://urlhaus.abuse.ch/url/" .. url_encode(url) .. "\n"
    end
    result = result .. "\nNote: URLhaus tracks malware distribution URLs.\n"
    
    return result
end

-- Format URLhaus host result
local function format_urlhaus_host_result(data, host)
    host = host or "unknown"
    
    if not data or data.query_status == "no_results" then
        return "=== URLhaus Host Intelligence ===\n\n" ..
               "Query: " .. host .. "\n\n" ..
               "No data available from URLhaus for this host.\n" ..
               "This could mean:\n" ..
               "- The host has not been observed hosting malware URLs\n" ..
               "- The host is not in URLhaus's database\n" ..
               "- The host is clean and has no associated threats"
    end
    
    local result = "=== URLhaus Host Intelligence ===\n\n"
    result = result .. "Query: " .. host .. "\n\n"
    
    -- URL count
    if data.url_count then
        result = result .. "--- Summary ---\n"
        result = result .. "Malware URLs Observed: " .. data.url_count .. "\n"
        if data.firstseen then
            result = result .. "First Seen: " .. data.firstseen .. "\n"
        end
        result = result .. "\n"
    end
    
    -- Blacklists
    if data.blacklists then
        result = result .. "--- Blacklist Status ---\n"
        if data.blacklists.spamhaus_dbl and data.blacklists.spamhaus_dbl ~= "not listed" then
            result = result .. "Spamhaus DBL: " .. data.blacklists.spamhaus_dbl .. " ⚠️\n"
        end
        if data.blacklists.surbl and data.blacklists.surbl == "listed" then
            result = result .. "SURBL: Listed ⚠️\n"
        end
        if (not data.blacklists.spamhaus_dbl or data.blacklists.spamhaus_dbl == "not listed") and
           (not data.blacklists.surbl or data.blacklists.surbl == "not listed") then
            result = result .. "Not listed on major blacklists\n"
        end
        result = result .. "\n"
    end
    
    -- URLs
    if data.urls and #data.urls > 0 then
        result = result .. "--- Malware URLs ---\n"
        local url_limit = math.min(10, #data.urls)
        for i = 1, url_limit do
            local url_data = data.urls[i]
            result = result .. i .. ". " .. (url_data.url or "unknown") .. "\n"
            if url_data.url_status then
                result = result .. "   Status: " .. url_data.url_status .. "\n"
            end
            if url_data.threat then
                result = result .. "   Threat: " .. url_data.threat .. "\n"
            end
            if url_data.tags and #url_data.tags > 0 then
                result = result .. "   Tags: " .. table.concat(url_data.tags, ", ") .. "\n"
            end
            result = result .. "\n"
        end
        if #data.urls > url_limit then
            result = result .. "... and " .. (#data.urls - url_limit) .. " more URL(s)\n\n"
        end
    end
    
    -- Link to URLhaus
    if data.urlhaus_reference then
        result = result .. "--- Additional Information ---\n"
        result = result .. "View full details: " .. data.urlhaus_reference .. "\n"
    else
        result = result .. "--- Additional Information ---\n"
        result = result .. "View full details: https://urlhaus.abuse.ch/host/" .. url_encode(host) .. "\n"
    end
    result = result .. "\nNote: URLhaus tracks malware distribution URLs.\n"
    
    return result
end

-- Format ThreatFox IOC result
local function format_threatfox_ioc_result(data, ioc)
    ioc = ioc or "unknown"
    
    if not data or data.query_status == "no_results" or data.query_status == "no_result" or not data.data or #data.data == 0 then
        return "=== ThreatFox IOC Intelligence ===\n\n" ..
               "Query: " .. ioc .. "\n\n" ..
               "No data available from ThreatFox for this IOC.\n" ..
               "This could mean:\n" ..
               "- The IOC has not been observed in any threat intelligence reports\n" ..
               "- The IOC is not in ThreatFox's database\n" ..
               "- The IOC is clean and has no associated threats"
    end
    
    local result = "=== ThreatFox IOC Intelligence ===\n\n"
    result = result .. "Query: " .. ioc .. "\n\n"
    
    -- Show up to 5 results
    local result_limit = math.min(5, #data.data)
    result = result .. "Found " .. #data.data .. " IOC(s) (showing " .. result_limit .. ")\n\n"
    
    for i = 1, result_limit do
        local ioc_data = data.data[i]
        result = result .. "--- IOC #" .. i .. " ---\n"
        
        if ioc_data.ioc then
            result = result .. "IOC: " .. ioc_data.ioc .. "\n"
        end
        
        if ioc_data.threat_type_desc then
            result = result .. "Threat Type: " .. ioc_data.threat_type_desc .. "\n"
        end
        
        if ioc_data.malware_printable then
            result = result .. "Malware Family: " .. ioc_data.malware_printable
            if ioc_data.malware_alias then
                result = result .. " (" .. ioc_data.malware_alias .. ")"
            end
            result = result .. "\n"
        end
        
        if ioc_data.confidence_level then
            result = result .. "Confidence Level: " .. ioc_data.confidence_level .. "/100\n"
        end
        
        if ioc_data.first_seen then
            result = result .. "First Seen: " .. ioc_data.first_seen .. "\n"
        end
        
        if ioc_data.last_seen then
            result = result .. "Last Seen: " .. ioc_data.last_seen .. "\n"
        end
        
        if ioc_data.tags and #ioc_data.tags > 0 then
            result = result .. "Tags: " .. table.concat(ioc_data.tags, ", ") .. "\n"
        end
        
        if ioc_data.reference then
            result = result .. "Reference: " .. ioc_data.reference .. "\n"
        end
        
        result = result .. "\n"
    end
    
    if #data.data > result_limit then
        result = result .. "... and " .. (#data.data - result_limit) .. " more IOC(s)\n\n"
    end
    
    result = result .. "--- Additional Information ---\n"
    result = result .. "View full details: https://threatfox.abuse.ch\n"
    result = result .. "\nNote: ThreatFox tracks IOCs (Indicators of Compromise) including botnet C&C servers.\n"
    
    return result
end

-- URLhaus URL callback
local function urlhaus_url_callback(...)
    local fields = {...}
    local url = get_field_value("http.request.full_uri", "display", fields)
    
    if not url then
        show_error_window("URLhaus URL Lookup", "Could not extract URL from packet")
        return
    end
    
    local data, err = lookup_urlhaus_url(url)
    if err then
        show_error_window("URLhaus Error", "Error querying URLhaus:\n" .. err)
        return
    end
    
    local formatted = format_urlhaus_url_result(data, url)
    show_result_window("URLhaus URL Intelligence: " .. url, formatted)
end

-- URLhaus host callback
local function urlhaus_host_callback(fieldname, ...)
    local fields = {...}
    local host_raw = get_field_value(fieldname, "display", fields)
    
    if not host_raw then
        show_error_window("URLhaus Host Lookup", "Could not extract host from packet")
        return
    end
    
    -- Extract IP or domain from the field value
    local host = extract_ip_from_string(host_raw) or host_raw
    if not host or host == "" then
        show_error_window("URLhaus Host Lookup", "Could not extract valid host from: " .. host_raw)
        return
    end
    
    -- Check if this is an RFC 1918 private address
    if is_rfc1918_private(host) then
        local formatted = format_rfc1918_info(host)
        show_result_window("Private IP Address: " .. host, formatted)
        return
    end
    
    local data, err = lookup_urlhaus_host(host)
    if err then
        show_error_window("URLhaus Error", "Error querying URLhaus:\n" .. err)
        return
    end
    
    local formatted = format_urlhaus_host_result(data, host)
    show_result_window("URLhaus Host Intelligence: " .. host, formatted)
end

-- ThreatFox IOC callback
local function threatfox_ioc_callback(fieldname, ...)
    local fields = {...}
    local ioc_raw = get_field_value(fieldname, "display", fields)
    
    if not ioc_raw then
        show_error_window("ThreatFox IOC Lookup", "Could not extract IOC from packet")
        return
    end
    
    -- Extract IP, domain, or use as-is for URL
    local ioc = extract_ip_from_string(ioc_raw) or ioc_raw
    if not ioc or ioc == "" then
        show_error_window("ThreatFox IOC Lookup", "Could not extract valid IOC from: " .. ioc_raw)
        return
    end
    
    -- Check if this is an RFC 1918 private address
    if is_rfc1918_private(ioc) then
        local formatted = format_rfc1918_info(ioc)
        show_result_window("Private IP Address: " .. ioc, formatted)
        return
    end
    
    local data, err = lookup_threatfox_ioc(ioc)
    if err then
        show_error_window("ThreatFox Error", "Error querying ThreatFox:\n" .. err)
        return
    end
    
    local formatted = format_threatfox_ioc_result(data, ioc)
    show_result_window("ThreatFox IOC Intelligence: " .. ioc, formatted)
end

-------------------------------------------------
-- TLS Certificate Analysis Module
-------------------------------------------------

local function analyze_tls_certificate(fields)
    local result = "=== TLS Certificate Analysis ===\n\n"
    
    -- Extract certificate information from TLS handshake fields
    local cert_subject = get_field_value("tls.handshake.certificate.subject", "value", fields)
    local cert_issuer = get_field_value("tls.handshake.certificate.issuer", "value", fields)
    local cert_sni = get_field_value("tls.handshake.extensions_server_name", "value", fields)
    
    -- Try alternative field names
    if not cert_subject then
        cert_subject = get_field_value("tls.handshake.certificate.subject.cn", "value", fields)
    end
    if not cert_issuer then
        cert_issuer = get_field_value("tls.handshake.certificate.issuer.cn", "value", fields)
    end
    
    -- Extract validity dates
    local cert_not_before = get_field_value("tls.handshake.certificate.validity.notBefore", "value", fields)
    local cert_not_after = get_field_value("tls.handshake.certificate.validity.notAfter", "value", fields)
    
    -- Extract serial number
    local cert_serial = get_field_value("tls.handshake.certificate.serialNumber", "value", fields)
    
    -- Extract certificate fingerprint
    local cert_fingerprint = get_field_value("tls.handshake.certificate.fingerprint", "value", fields)
    if not cert_fingerprint then
        cert_fingerprint = get_field_value("tls.handshake.certificate.fingerprint.sha256", "value", fields)
    end
    
    -- Check if we have any certificate data
    if not cert_subject and not cert_issuer and not cert_sni then
        return nil, "Could not extract certificate information from TLS handshake.\n\n" ..
                   "Make sure you're right-clicking on a TLS Certificate message packet."
    end
    
    result = result .. "--- Certificate Information ---\n"
    
    if cert_sni then
        result = result .. "Server Name (SNI): " .. cert_sni .. "\n"
    end
    
    if cert_subject then
        result = result .. "Subject: " .. cert_subject .. "\n"
    end
    
    if cert_issuer then
        result = result .. "Issuer: " .. cert_issuer .. "\n"
        
        -- Security check: self-signed certificate
        if cert_subject and cert_issuer == cert_subject then
            result = result .. "⚠ WARNING: Self-signed certificate detected!\n"
        end
        
        -- Check for well-known issuers
        if cert_issuer then
            local well_known_issuers = {
                "Let's Encrypt",
                "DigiCert",
                "GlobalSign",
                "Go Daddy",
                "COMODO",
                "Sectigo",
                "Amazon",
                "Google",
                "Microsoft",
                "Cloudflare",
                "GoDaddy",
                "Thawte",
                "VeriSign",
                "Entrust",
                "GeoTrust"
            }
            
            local is_known = false
            for _, known_issuer in ipairs(well_known_issuers) do
                if string.find(cert_issuer, known_issuer) then
                    is_known = true
                    break
                end
            end
            
            if not is_known and cert_issuer ~= cert_subject then
                result = result .. "ℹ Note: Issuer may not be a well-known CA\n"
            end
        end
    end
    
    if cert_serial then
        result = result .. "Serial Number: " .. cert_serial .. "\n"
    end
    
    if cert_fingerprint then
        result = result .. "Fingerprint: " .. cert_fingerprint .. "\n"
    end
    
    -- Validity period analysis
    if cert_not_before or cert_not_after then
        result = result .. "\n--- Validity Period ---\n"
        if cert_not_before then
            result = result .. "Valid From: " .. cert_not_before .. "\n"
        end
        if cert_not_after then
            result = result .. "Valid Until: " .. cert_not_after .. "\n"
            
            -- Check if expired
            -- Try to parse date (format varies: "20250129" or "Jan 29 12:00:00 2025 GMT")
            local year = string.match(cert_not_after, "(%d%d%d%d)")
            if year then
                local year_num = tonumber(year)
                local current_year = tonumber(os.date("%Y"))
                if year_num < current_year then
                    result = result .. "⚠ WARNING: Certificate is EXPIRED\n"
                elseif year_num == current_year then
                    -- Check month/day if possible
                    local month = string.match(cert_not_after, "(%d%d)")
                    if month then
                        local month_num = tonumber(month)
                        local current_month = tonumber(os.date("%m"))
                        if month_num < current_month then
                            result = result .. "⚠ WARNING: Certificate is EXPIRED\n"
                        end
                    end
                end
            end
        end
    end
    
    -- Security recommendations
    result = result .. "\n--- Security Analysis ---\n"
    
    if cert_subject and cert_issuer and cert_subject == cert_issuer then
        result = result .. "⚠ Self-signed certificate - verify authenticity manually\n"
    end
    
    if cert_sni and cert_subject then
        -- Check if SNI matches certificate subject
        local sni_domain = cert_sni
        local subject_domain = string.match(cert_subject, "CN=([^,]+)") or cert_subject
        if not string.find(subject_domain, sni_domain) and not string.find(sni_domain, subject_domain) then
            result = result .. "⚠ SNI domain may not match certificate subject\n"
        end
    end
    
    -- Check Certificate Transparency if we have a domain
    local domain_to_check = cert_sni
    if not domain_to_check and cert_subject then
        domain_to_check = string.match(cert_subject, "CN=([^,]+)") or string.match(cert_subject, "([%w%.%-]+%.[%w%.%-]+)")
    end
    
    if domain_to_check and CONFIG.CERT_TRANSPARENCY_ENABLED then
        result = result .. "\n--- Certificate Transparency Check ---\n"
        result = result .. "Checking CT logs for: " .. domain_to_check .. "\n"
        result = result .. "(This may take a moment...)\n"
        
        -- Lookup in CT logs
        local ct_data, ct_err = lookup_certificate_transparency(domain_to_check)
        if not ct_err and ct_data and type(ct_data) == "table" and #ct_data > 0 then
            result = result .. "✓ Found " .. #ct_data .. " certificate(s) in CT logs\n"
            
            -- Try to match serial number if available
            if cert_serial then
                local found_match = false
                for i, cert in ipairs(ct_data) do
                    if i <= 5 and cert.serial_number == cert_serial then
                        result = result .. "✓ Certificate serial matches CT log entry #" .. i .. "\n"
                        found_match = true
                        break
                    end
                end
                if not found_match then
                    result = result .. "ℹ Certificate serial not found in CT logs (may be new or private)\n"
                end
            end
        else
            result = result .. "ℹ Certificate not found in CT logs\n"
            result = result .. "  (This is normal for private/internal certificates)\n"
        end
    end
    
    result = result .. "\n--- Recommendations ---\n"
    result = result .. "• Verify certificate issuer is trusted\n"
    result = result .. "• Check certificate validity dates\n"
    result = result .. "• Verify certificate subject matches expected domain\n"
    result = result .. "• Review certificate chain for trust issues\n"
    if cert_fingerprint then
        result = result .. "• Search certificate fingerprint: " .. cert_fingerprint .. "\n"
    end
    
    return result, nil
end

local function tls_certificate_callback(...)
    local fields = {...}
    
    local result, err = analyze_tls_certificate(fields)
    if err then
        show_error_window("TLS Certificate Analysis Error", err)
        return
    end
    
    show_result_window("TLS Certificate Analysis", result)
end

-- TLS Certificate Analysis for TCP/443 packets
local function tls_tcp443_callback(fieldname, ...)
    local fields = {...}
    
    -- Check if this is port 443
    local port = get_field_value(fieldname, "value", fields)
    if not port or (tonumber(port) ~= 443) then
        -- Not port 443, skip
        return
    end
    
    -- Try to extract certificate information
    local cert_subject = get_field_value("tls.handshake.certificate.subject", "value", fields)
    local cert_issuer = get_field_value("tls.handshake.certificate.issuer", "value", fields)
    local cert_sni = get_field_value("tls.handshake.extensions_server_name", "value", fields)
    
    -- Try alternative field names
    if not cert_subject then
        cert_subject = get_field_value("tls.handshake.certificate.subject.cn", "value", fields)
    end
    if not cert_issuer then
        cert_issuer = get_field_value("tls.handshake.certificate.issuer.cn", "value", fields)
    end
    
    -- If we have certificate data, analyze it
    if cert_subject or cert_issuer or cert_sni then
        local result, err = analyze_tls_certificate(fields)
        if err then
            show_error_window("TLS Certificate Analysis Error", err)
            return
        end
        show_result_window("TLS Certificate Analysis", result)
        return
    end
    
    -- No certificate data available - show helpful message
    local hostname = cert_sni
    if not hostname then
        hostname = get_field_value("http.host", "value", fields)
    end
    
    local message = "=== TLS Certificate Analysis ===\n\n"
    message = message .. "This packet is part of a TCP/443 (HTTPS) session.\n\n"
    
    if hostname then
        message = message .. "Hostname: " .. hostname .. "\n\n"
    end
    
    message = message .. "⚠ Certificate data not available in this packet.\n\n"
    message = message .. "Possible reasons:\n"
    message = message .. "• This packet doesn't contain the TLS handshake\n"
    message = message .. "• Certificate exchange hasn't occurred yet\n"
    message = message .. "• This is a data packet, not a handshake packet\n"
    message = message .. "• TLS session is encrypted (no certificate visible)\n\n"
    
    message = message .. "--- Recommended Actions ---\n\n"
    
    
    message = message .. "✓ Find the TLS Handshake packet:\n"
    message = message .. "  • Filter: tls.handshake.type == 11 (Certificate)\n"
    message = message .. "  • Right-click on certificate fields in that packet\n\n"
    
    message = message .. "✓ Use Certificate Transparency:\n"
    if CONFIG.CERT_TRANSPARENCY_ENABLED then
        message = message .. "  Right-click on DNS query or TLS SNI → ASK → Certificate Transparency\n"
    else
        message = message .. "  Enable Certificate Transparency in plugin config\n"
    end
    
    show_result_window("TLS Certificate Analysis", message)
end

-------------------------------------------------
-- Certificate Validity Checker (OpenSSL)
-------------------------------------------------

-- Execute command silently on Windows (suppress command window)
-- This function is used by certificate check and DNS functions
local function execute_silent_cert(cmd)
    local is_windows = package.config:sub(1,1) == "\\"
    
    if is_windows then
        -- On Windows, use VBScript to run command completely silently (no window flash)
        local temp_out = os.tmpname() .. ".txt"
        local temp_vbs = os.tmpname() .. ".vbs"
        
        -- Escape quotes in command for VBScript (double them)
        local escaped_cmd = cmd:gsub('"', '""')
        
        -- Create VBScript that runs command silently (window style 0 = hidden)
        local vbs_content = string.format([[
Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
WshShell.Run "cmd /c %s > ""%s"" 2>&1", 0, True
Set f = fso.OpenTextFile("%s", 1)
If Not f.AtEndOfStream Then
    WScript.StdOut.Write f.ReadAll
End If
f.Close
fso.DeleteFile "%s"
]], escaped_cmd, temp_out, temp_out, temp_out)
        
        local vbs_file = io.open(temp_vbs, "w")
        if vbs_file then
            vbs_file:write(vbs_content)
            vbs_file:close()
            
            -- Execute VBScript (runs silently, //nologo suppresses VBScript banner)
            local handle = io.popen(string.format('cscript //nologo "%s"', temp_vbs))
            local output = ""
            if handle then
                output = handle:read("*a") or ""
                handle:close()
            end
            
            -- Clean up VBScript file
            os.remove(temp_vbs)
            
            return output
        end
        
        -- Fallback: use io.popen if VBScript creation fails
        local handle = io.popen(cmd .. " 2>&1")
        if handle then
            local result = handle:read("*a") or ""
            handle:close()
            return result
        end
        return ""
    else
        -- On Unix-like systems, use io.popen normally
        local handle = io.popen(cmd .. " 2>&1")
        if handle then
            local result = handle:read("*a") or ""
            handle:close()
            return result
        end
        return ""
    end
end

-- Query SSLLabs API for certificate and TLS analysis
local function check_certificate_ssllabs(hostname, port)
    port = port or 443
    
    -- Remove protocol prefix if present
    local domain = string.gsub(hostname, "^https?://", "")
    domain = string.gsub(domain, "^www%.", "")
    
    -- SSLLabs API endpoint (free, no API key required)
    local api_url = "https://api.ssllabs.com/api/v3/analyze?host=" .. domain
    
    log_message("Querying SSLLabs API for certificate: " .. domain)
    
    -- Step 1: Start a new assessment (or get cached results)
    -- Use startNew=off to prefer cached results, fromCache=on to allow cache
    local start_url = api_url .. "&startNew=off&fromCache=on&all=done"
    
    local response, err = http_get(start_url, {})
    if err then
        return nil, "SSLLabs API query failed: " .. err
    end
    
    if not response or response == "" then
        return nil, "Empty response from SSLLabs API"
    end
    
    -- Parse initial JSON response
    local json_data = parse_json(response)
    if not json_data then
        return nil, "Failed to parse SSLLabs API JSON response"
    end
    
    -- Check for errors in response
    if json_data.errors and #json_data.errors > 0 then
        local error_msg = json_data.errors[1].message or "Unknown error from SSLLabs API"
        return nil, error_msg
    end
    
    -- Check status: READY, IN_PROGRESS, DNS, ERROR
    local status = json_data.status
    
    if status == "ERROR" then
        return nil, "SSLLabs API returned error for domain: " .. domain
    end
    
    -- If not ready, we need to poll
    if status ~= "READY" then
        log_message("SSLLabs assessment in progress, status: " .. status)
        
        -- Poll up to 30 times with 2 second delay (60 seconds max)
        local max_polls = 30
        local poll_delay = 2
        
        for i = 1, max_polls do
            -- Sleep using os.execute (cross-platform)
            local sleep_cmd
            if package.config:sub(1,1) == "\\" then
                sleep_cmd = "timeout /t " .. poll_delay .. " >nul 2>&1"
            else
                sleep_cmd = "sleep " .. poll_delay
            end
            os.execute(sleep_cmd)
            
            -- Poll for status
            log_message("Polling SSLLabs API (attempt " .. i .. "/" .. max_polls .. ")...")
            response, err = http_get(api_url .. "&all=done", {})
            
            if err then
                return nil, "SSLLabs API polling failed: " .. err
            end
            
            json_data = parse_json(response)
            if not json_data then
                return nil, "Failed to parse SSLLabs API poll response"
            end
            
            status = json_data.status
            log_message("Poll status: " .. status)
            
            if status == "READY" then
                break
            elseif status == "ERROR" then
                return nil, "SSLLabs API assessment failed for: " .. domain
            end
        end
        
        if status ~= "READY" then
            return nil, "SSLLabs API assessment timeout (still in progress). Try again in a few minutes.\n\nNote: SSLLabs performs comprehensive analysis which can take 60-120 seconds for first scan."
        end
    end
    
    -- Extract certificate and TLS information from SSLLabs response
    local result = {}
    result.hostname = domain
    result.port = port
    result.source = "SSLLabs API"
    result.raw_data = json_data  -- Store for detailed analysis
    
    -- Overall grade
    if json_data.endpoints and #json_data.endpoints > 0 then
        local endpoint = json_data.endpoints[1]
        if endpoint.grade then
            result.grade = endpoint.grade
        end
        
        -- Get detailed endpoint data
        if endpoint.details then
            local details = endpoint.details
            
            -- Certificate information
            if details.cert then
                local cert = details.cert
                
                if cert.subject then
                    result.subject = cert.subject
                end
                
                if cert.issuerSubject then
                    result.issuer = cert.issuerSubject
                end
                
                if cert.notBefore then
                    -- Convert from milliseconds timestamp
                    result.notBefore = os.date("%Y-%m-%d %H:%M:%S UTC", cert.notBefore / 1000)
                end
                
                if cert.notAfter then
                    -- Convert from milliseconds timestamp
                    local expiry_time = cert.notAfter / 1000
                    result.notAfter = os.date("%Y-%m-%d %H:%M:%S UTC", expiry_time)
                    
                    -- Calculate days until expiry
                    local current_time = os.time()
                    local days_remaining = math.floor((expiry_time - current_time) / 86400)
                    result.daysUntilExpiry = days_remaining
                    result.isExpired = days_remaining < 0
                end
                
                if cert.serialNumber then
                    result.serial = cert.serialNumber
                end
                
                if cert.sigAlg then
                    result.algorithm = cert.sigAlg
                end
                
                if cert.altNames then
                    result.sans = table.concat(cert.altNames, ", ")
                end
                
                if cert.sha1Hash then
                    result.sha1 = cert.sha1Hash
                end
                
                if cert.sha256Hash then
                    result.sha256 = cert.sha256Hash
                end
            end
            
            -- Protocol support
            if details.protocols then
                local protocols = {}
                for _, proto in ipairs(details.protocols) do
                    table.insert(protocols, proto.name .. " " .. proto.version)
                end
                result.protocols = table.concat(protocols, ", ")
            end
            
            -- Vulnerabilities
            result.vulnerabilities = {}
            if details.vulnBeast then result.vulnerabilities.BEAST = details.vulnBeast end
            if details.heartbleed then result.vulnerabilities.Heartbleed = details.heartbleed end
            if details.poodle then result.vulnerabilities.POODLE = details.poodle end
            if details.freak then result.vulnerabilities.FREAK = details.freak end
            if details.logjam then result.vulnerabilities.Logjam = details.logjam end
            if details.drownVulnerable then result.vulnerabilities.DROWN = details.drownVulnerable end
            
            -- Additional security features
            if details.supportsRc4 ~= nil then
                result.supportsRc4 = details.supportsRc4
            end
            
            if details.forwardSecrecy then
                result.forwardSecrecy = details.forwardSecrecy
            end
            
            if details.hstsPolicy then
                result.hsts = details.hstsPolicy.status or "unknown"
                if details.hstsPolicy.maxAge then
                    result.hstsMaxAge = details.hstsPolicy.maxAge
                end
            end
        end
    end
    
    return result, nil
end

-- crt.sh API for certificate transparency lookup
-- This provides historical certificate information from CT logs
local function check_certificate_crtsh(hostname)
    -- Remove protocol prefix if present
    local domain = string.gsub(hostname, "^https?://", "")
    domain = string.gsub(domain, "^www%.", "")
    
    log_message("Querying crt.sh for certificate: " .. domain)
    
    -- crt.sh JSON API endpoint
    local api_url = string.format("https://crt.sh/?q=%s&output=json", domain)
    
    -- Make HTTP GET request
    local response, err = http_get(api_url, {})
    if err then
        return nil, "crt.sh API query failed: " .. err
    end
    
    if not response or response == "" then
        return nil, "Empty response from crt.sh API"
    end
    
    -- Parse JSON response (returns an array of certificates)
    local json_data = parse_json(response)
    if not json_data or type(json_data) ~= "table" then
        return nil, "Failed to parse crt.sh API response"
    end
    
    if #json_data == 0 then
        return nil, "No certificates found for " .. domain .. " in Certificate Transparency logs"
    end
    
    -- Get the most recent certificate (first in list, sorted by not_before desc)
    local cert = json_data[1]
    
    -- Extract certificate information
    local result = {}
    result.hostname = domain
    result.port = 443
    result.source = "crt.sh (Certificate Transparency)"
    
    if cert.common_name then
        result.subject = cert.common_name
    end
    
    if cert.issuer_name then
        result.issuer = cert.issuer_name
    end
    
    if cert.not_before then
        result.notBefore = cert.not_before
    end
    
    if cert.not_after then
        result.notAfter = cert.not_after
        -- Check if expired
        local year, month, day = string.match(cert.not_after, "(%d+)-(%d+)-(%d+)")
        if year then
            local expiry_time = os.time({year=tonumber(year), month=tonumber(month), day=tonumber(day)})
            local now = os.time()
            result.isExpired = (expiry_time < now)
            result.daysUntilExpiry = math.floor((expiry_time - now) / 86400)
        end
    end
    
    if cert.serial_number then
        result.serial = cert.serial_number
    end
    
    -- Include CT log info
    result.ctLogId = cert.id
    result.ctLogEntryTimestamp = cert.entry_timestamp
    
    -- Count total certificates found
    result.totalCertsFound = #json_data
    
    return result, nil
end

-- OpenSSL-based basic certificate check (quick and simple)
-- Note: Caller should check OpenSSL availability first using check_openssl_available()
local function check_certificate_openssl(hostname, port)
    port = port or 443
    
    -- Remove protocol prefix if present
    hostname = string.gsub(hostname, "^https?://", "")
    hostname = string.gsub(hostname, "^www%.", "")
    
    local is_windows = package.config:sub(1,1) == "\\"
    local cmd
    local output
    
    log_message("Using OpenSSL for: " .. hostname .. ":" .. port)
    
    if is_windows then
        -- Windows: Build the OpenSSL command and run silently
        cmd = string.format('echo. | openssl s_client -connect %s:%d -servername %s 2>nul | openssl x509 -noout -dates -subject -issuer', hostname, port, hostname)
        
        -- Use execute_silent to avoid window flash
        output = execute_silent(cmd)
    else
        -- Unix-like: use pipe directly (no window issues)
        cmd = string.format("echo | openssl s_client -connect %s:%d -servername %s 2>/dev/null | openssl x509 -noout -dates -subject -issuer 2>&1", hostname, port, hostname)
        local handle = io.popen(cmd)
        if handle then
            output = handle:read("*a")
            handle:close()
        end
    end
    
    if not output or output == "" then
        return nil, "No certificate information returned from OpenSSL.\n\n" ..
                   "This could mean:\n" ..
                   "• OpenSSL is not installed or not in PATH\n" ..
                   "• The host is unreachable or not responding on port " .. port .. "\n" ..
                   "• The connection timed out\n\n" ..
                   "Please verify OpenSSL is installed and the host is accessible."
    end
    
    -- Parse certificate information
    local result = {}
    result.hostname = hostname
    result.port = port
    result.source = "OpenSSL (fallback)"
    
    -- Extract subject
    local subject = string.match(output, "subject=([^\n]+)")
    if subject then
        result.subject = subject
    end
    
    -- Extract issuer
    local issuer = string.match(output, "issuer=([^\n]+)")
    if issuer then
        result.issuer = issuer
    end
    
    -- Extract notBefore date
    local not_before = string.match(output, "notBefore=([^\n]+)")
    if not_before then
        result.notBefore = not_before
    end
    
    -- Extract notAfter date
    local not_after = string.match(output, "notAfter=([^\n]+)")
    if not_after then
        result.notAfter = not_after
        
        -- Simple expiry check
        local year = string.match(not_after, "(%d%d%d%d)")
        if year then
            local year_num = tonumber(year)
            local current_year = tonumber(os.date("%Y"))
            result.isExpired = (year_num < current_year)
        end
    end
    
    return result, nil
end

local function check_certificate_validity(hostname, port)
    port = port or 443
    
    -- Try SSLLabs API (no API key required, comprehensive analysis)
    if ensure_curl_checked() then
        log_message("Attempting certificate check via SSLLabs API")
        local api_result, api_err = check_certificate_ssllabs(hostname, port)
        if not api_err and api_result then
            log_message("SSLLabs API certificate check successful")
            return api_result, nil
        elseif api_err then
            log_message("SSLLabs API certificate check failed: " .. api_err)
            
            -- Check if it's a capacity error (rate limiting)
            if string.find(api_err:lower(), "capacity") or string.find(api_err:lower(), "try again later") then
                -- Try OpenSSL fallback
                local openssl_available = check_openssl_available()
                if openssl_available then
                    log_message("SSLLabs at capacity, trying OpenSSL fallback...")
                    local openssl_result, openssl_err = check_certificate_openssl(hostname, port)
                    if not openssl_err and openssl_result then
                        log_message("OpenSSL fallback successful")
                        return openssl_result, nil
                    else
                        -- Both failed, return informative error
                        return nil, "⚠ SSLLabs API Error: Running at full capacity. Please try again later.\n\n" ..
                                   "OpenSSL fallback also failed: " .. (openssl_err or "unknown error") .. "\n\n" ..
                                   "Note: SSLLabs provides comprehensive security analysis but may be busy.\n" ..
                                   "Try again in a few minutes for full security grading and vulnerability detection."
                    end
                else
                    -- No OpenSSL available
                    return nil, "⚠ SSLLabs API Error: Running at full capacity. Please try again later.\n\n" ..
                               "Note: SSLLabs provides comprehensive security analysis but may be busy during peak times.\n" ..
                               "Please try again in a few minutes for full security grading and vulnerability detection.\n\n" ..
                               "Alternative: Install OpenSSL for basic certificate checking as a fallback option.\n" ..
                               "  • macOS: brew install openssl\n" ..
                               "  • Linux: apt-get/yum/dnf install openssl\n" ..
                               "  • Windows: Download from https://slproweb.com/products/Win32OpenSSL.html"
                end
            else
                -- Other error, return as-is
                return nil, api_err
            end
        end
    else
        return nil, "curl is not available. SSLLabs API requires curl for HTTPS requests."
    end
    
    return nil, "Certificate check failed"
end

local function format_cert_validity_result(data, hostname)
    if not data then
        return "=== SSL/TLS Certificate & Security Analysis ===\n\n" ..
               "No certificate data available for: " .. (hostname or "unknown")
    end
    
    local result = "=== SSL/TLS Certificate & Security Analysis ===\n\n"
    
    -- Show which method was used
    if data.source == "SSLLabs API" then
        result = result .. "--- Data Source ---\n"
        result = result .. "Method: SSLLabs API v3 (Qualys SSL Labs)\n"
        result = result .. "• Comprehensive SSL/TLS security analysis\n"
        result = result .. "• Industry-standard security grading\n"
        result = result .. "• Vulnerability detection (Heartbleed, POODLE, etc.)\n"
        result = result .. "• Free service, no API key required\n\n"
    elseif data.source == "OpenSSL (fallback)" or data.source == "OpenSSL" then
        result = result .. "--- Data Source ---\n"
        if data.source == "OpenSSL (fallback)" then
            result = result .. "Method: OpenSSL (fallback - SSLLabs unavailable)\n"
            result = result .. "⚠ Note: SSLLabs was at capacity. Using OpenSSL for basic check.\n\n"
        else
            result = result .. "Method: OpenSSL (Quick Check)\n"
        end
        result = result .. "• Basic certificate validation\n"
        result = result .. "• Direct connection to server\n"
        result = result .. "• Fast, no external API dependencies\n\n"
    elseif data.source == "crt.sh (Certificate Transparency)" then
        result = result .. "--- Data Source ---\n"
        result = result .. "Method: crt.sh (Certificate Transparency Logs)\n"
        result = result .. "• Shows certificates logged to CT logs\n"
        result = result .. "• Historical certificate data\n"
        result = result .. "• Free service, no API key required\n"
        if data.totalCertsFound and data.totalCertsFound > 1 then
            result = result .. "• Found " .. data.totalCertsFound .. " certificates for this domain\n"
        end
        result = result .. "\n"
    end
    
    result = result .. "Host: " .. (data.hostname or hostname or "unknown") .. "\n"
    result = result .. "Port: " .. tostring(data.port or 443) .. "\n"
    
    -- SSLLabs overall grade
    if data.grade then
        result = result .. "\n--- Overall Security Grade ---\n"
        local grade_color = ""
        if data.grade == "A+" or data.grade == "A" then
            grade_color = "✓ "
        elseif data.grade:match("^[BC]") then
            grade_color = "⚠ "
        else
            grade_color = "⚠⚠ "
        end
        result = result .. grade_color .. "Grade: " .. data.grade .. "\n"
        result = result .. "(A+ is best, F is worst)\n"
    end
    
    result = result .. "\n--- Certificate Information ---\n"
    
    if data.subject then
        result = result .. "Subject: " .. data.subject .. "\n"
    end
    
    if data.issuer then
        result = result .. "Issuer: " .. data.issuer .. "\n"
    end
    
    -- Additional certificate details from API
    if data.serial then
        result = result .. "Serial Number: " .. data.serial .. "\n"
    end
    
    if data.algorithm then
        result = result .. "Signature Algorithm: " .. data.algorithm .. "\n"
    end
    
    if data.notBefore then
        result = result .. "\nValid From: " .. data.notBefore .. "\n"
    end
    
    if data.notAfter then
        result = result .. "Valid Until: " .. data.notAfter .. "\n"
        
        if data.isExpired then
            result = result .. "\n⚠⚠⚠ WARNING: Certificate is EXPIRED ⚠⚠⚠\n"
        elseif data.daysUntilExpiry then
            if data.daysUntilExpiry <= 7 then
                result = result .. "\n⚠⚠ WARNING: Certificate expires in " .. data.daysUntilExpiry .. " days!\n"
            elseif data.daysUntilExpiry <= 30 then
                result = result .. "\n⚠ WARNING: Certificate expires in " .. data.daysUntilExpiry .. " days\n"
            else
                result = result .. "\n✓ Certificate is valid for " .. data.daysUntilExpiry .. " more days\n"
            end
        elseif data.expiresThisYear then
            result = result .. "\n!! Certificate expires this year !!\n"
        else
            result = result .. "\n✓ Certificate is valid\n"
        end
    end
    
    -- Protocol support
    if data.protocols then
        result = result .. "\n--- Supported Protocols ---\n"
        result = result .. data.protocols .. "\n"
    end
    
    -- Additional information from API
    if data.sans then
        result = result .. "\n--- Subject Alternative Names (SANs) ---\n"
        if type(data.sans) == "table" then
            for _, san in ipairs(data.sans) do
                result = result .. "• " .. san .. "\n"
            end
        else
            result = result .. data.sans .. "\n"
        end
    end
    
    -- Certificate fingerprints
    if data.sha1 or data.sha256 then
        result = result .. "\n--- Certificate Fingerprints ---\n"
        if data.sha256 then
            result = result .. "SHA256: " .. data.sha256 .. "\n"
        end
        if data.sha1 then
            result = result .. "SHA1: " .. data.sha1 .. "\n"
        end
    end
    
    -- Vulnerabilities check
    if data.vulnerabilities and next(data.vulnerabilities) then
        result = result .. "\n--- Vulnerability Assessment ---\n"
        local has_vulns = false
        for vuln_name, vuln_status in pairs(data.vulnerabilities) do
            if vuln_status == true then
                result = result .. "⚠⚠ VULNERABLE: " .. vuln_name .. "\n"
                has_vulns = true
            elseif vuln_status == false then
                result = result .. "✓ Not vulnerable: " .. vuln_name .. "\n"
            end
        end
        if not has_vulns then
            result = result .. "✓ No known vulnerabilities detected\n"
        end
    end
    
    -- Security features
    if data.forwardSecrecy or data.supportsRc4 ~= nil or data.hsts then
        result = result .. "\n--- Security Features ---\n"
        
        if data.forwardSecrecy then
            local fs_str = tostring(data.forwardSecrecy)
            if fs_str:find("4") then  -- Forward secrecy with all ciphers
                result = result .. "✓ Forward Secrecy: Enabled (all ciphers)\n"
            elseif fs_str:find("2") then  -- Forward secrecy with modern ciphers
                result = result .. "✓ Forward Secrecy: Enabled (modern ciphers)\n"
            else
                result = result .. "Forward Secrecy: " .. fs_str .. "\n"
            end
        end
        
        if data.supportsRc4 ~= nil then
            if data.supportsRc4 then
                result = result .. "⚠ RC4 Support: Enabled (insecure, should be disabled)\n"
            else
                result = result .. "✓ RC4 Support: Disabled (good)\n"
            end
        end
        
        if data.hsts then
            result = result .. "HSTS: " .. tostring(data.hsts)
            if data.hstsMaxAge then
                result = result .. " (max-age: " .. data.hstsMaxAge .. " seconds)"
            end
            result = result .. "\n"
        end
    end
    
    result = result .. "\n--- Security Recommendations ---\n"
    if data.isExpired then
        result = result .. "⚠⚠ URGENT: Certificate is expired!\n"
        result = result .. "• Replace certificate immediately\n"
        result = result .. "• Check certificate renewal process\n"
        result = result .. "• Users will see security warnings\n"
    elseif data.daysUntilExpiry and data.daysUntilExpiry <= 30 then
        result = result .. "⚠ Certificate expires soon - plan renewal\n"
        result = result .. "• Set up automatic certificate renewal\n"
        result = result .. "• Consider using Let's Encrypt for auto-renewal\n"
    else
        result = result .. "✓ Certificate validity period is good\n"
    end
    
    -- Grade-specific recommendations
    if data.grade then
        if data.grade:match("^[FT]") then
            result = result .. "⚠⚠ Grade " .. data.grade .. " indicates serious security issues\n"
            result = result .. "• Review SSLLabs report for detailed issues\n"
            result = result .. "• Update TLS configuration immediately\n"
        elseif data.grade:match("^[CD]") then
            result = result .. "⚠ Grade " .. data.grade .. " indicates configuration weaknesses\n"
            result = result .. "• Improve cipher suite selection\n"
            result = result .. "• Enable forward secrecy\n"
            result = result .. "• Disable weak protocols (SSLv3, TLS 1.0)\n"
        elseif data.grade == "B" then
            result = result .. "Grade B is acceptable but can be improved\n"
            result = result .. "• Review SSLLabs recommendations\n"
        end
    end
    
    if data.supportsRc4 then
        result = result .. "• Disable RC4 cipher support (insecure)\n"
    end
    
    result = result .. "\n--- Additional Resources ---\n"
    result = result .. "• Full SSLLabs Report: https://www.ssllabs.com/ssltest/analyze.html?d=" .. (data.hostname or hostname or "") .. "\n"
    result = result .. "• Mozilla SSL Configuration Generator: https://ssl-config.mozilla.org/\n"
    
    return result
end

-- Helper function to extract hostname for certificate checks
local function extract_hostname_for_cert_check(fields, operation_name)
    local hostname = get_field_value("tls.handshake.extensions_server_name", "value", fields)
    
    if not hostname then
        hostname = get_field_value("http.host", "value", fields)
    end
    
    if not hostname then
        show_error_window(operation_name, "Could not extract hostname from packet.\n\n" ..
                         "This check requires a hostname to connect to the server.\n\n" ..
                         "Please right-click on:\n" ..
                         "• TLS Client Hello with SNI (tls.handshake.extensions_server_name)\n" ..
                         "   - This is in the Client Hello message where the client specifies the server name\n\n" ..
                         "• HTTP Host header (http.host)\n" ..
                         "   - This is in HTTP requests where the Host header is present\n\n" ..
                         "Note: Certificate fields (tls.handshake.certificate.*) do not contain\n" ..
                         "the hostname being accessed, only the certificate subject which may differ.")
        return nil
    end
    
    -- Remove protocol prefix if present
    hostname = string.gsub(hostname, "^https?://", "")
    hostname = string.gsub(hostname, "^www%.", "")
    
    -- Get port from packet if available
    local port = 443
    local tcp_port = get_field_value("tcp.dstport", "value", fields)
    if tcp_port and tonumber(tcp_port) then
        port = tonumber(tcp_port)
    end
    
    return hostname, port
end

-- 1. Quick Certificate Check (OpenSSL) - Fast and simple
local function quick_cert_check_callback(...)
    local fields = {...}
    local hostname, port = extract_hostname_for_cert_check(fields, "Quick Certificate Check")
    if not hostname then return end
    
    -- Check if OpenSSL is available
    local openssl_available = check_openssl_available()
    if not openssl_available then
        show_error_window("OpenSSL Not Available", 
                         "OpenSSL is required for quick certificate checking.\n\n" ..
                         "Installation:\n" ..
                         "• macOS: brew install openssl\n" ..
                         "• Linux: apt-get/yum/dnf install openssl\n" ..
                         "• Windows: Download from https://slproweb.com/products/Win32OpenSSL.html\n\n" ..
                         "Alternative: Use 'Certificate Validator' for API-based checking (no OpenSSL required)")
        return
    end
    
    local data, err = check_certificate_openssl(hostname, port)
    if err then
        show_error_window("Quick Certificate Check Error", "Error checking certificate:\n" .. err)
        return
    end
    
    data.source = "OpenSSL"  -- Mark as intentional OpenSSL use
    local formatted = format_cert_validity_result(data, hostname)
    show_result_window_with_buttons("Quick Certificate Check: " .. hostname, formatted, "Quick Certificate Check", hostname)
end

-- 2. Certificate Validator (crt.sh - Certificate Transparency) - Shows certificate history
local function cert_validator_callback(...)
    local fields = {...}
    local hostname, port = extract_hostname_for_cert_check(fields, "Certificate Validator")
    if not hostname then return end
    
    if not ensure_curl_checked() then
        show_error_window("curl Not Available", "curl is required for crt.sh API.\n\nPlease install curl first.")
        return
    end
    
    local data, err = check_certificate_crtsh(hostname)
    if err then
        -- Try OpenSSL fallback
        local openssl_available = check_openssl_available()
        if openssl_available then
            log_message("crt.sh failed, trying OpenSSL fallback...")
            data, err = check_certificate_openssl(hostname, port)
            if not err and data then
                data.source = "OpenSSL (fallback)"
            end
        end
        
        if err then
            show_error_window("Certificate Validator Error", "Error checking certificate:\n" .. err)
            return
        end
    end
    
    local formatted = format_cert_validity_result(data, hostname)
    show_result_window_with_buttons("Certificate Validator: " .. hostname, formatted, "Certificate Validator", hostname)
end

-- 3. SSL Security Analysis (SSLLabs) - Comprehensive but slower
local function ssl_security_analysis_callback(...)
    local fields = {...}
    local hostname, port = extract_hostname_for_cert_check(fields, "SSL Security Analysis")
    if not hostname then return end
    
    -- Check certificate validity using SSLLabs (with automatic OpenSSL fallback on capacity errors)
    local data, err = check_certificate_validity(hostname, port)
    if err then
        show_error_window("SSL Security Analysis Error", "Error checking certificate:\n" .. err)
        return
    end
    
    local formatted = format_cert_validity_result(data, hostname)
    show_result_window_with_buttons("SSL Security Analysis: " .. hostname, formatted, "SSL Security Analysis", hostname)
end

-- Legacy callback for backward compatibility (uses comprehensive check)
local function cert_validity_callback(...)
    ssl_security_analysis_callback(...)
end

-------------------------------------------------
-- DNS Analytics Module for IP Addresses
-------------------------------------------------

-- Convert IP address to reverse DNS format for PTR queries
local function ip_to_reverse_dns(ip)
    if not ip or ip == "" then
        return nil
    end
    
    if is_valid_ipv4(ip) then
        -- IPv4: reverse octets and append .in-addr.arpa
        -- e.g., 1.2.3.4 -> 4.3.2.1.in-addr.arpa
        local parts = {}
        for part in string.gmatch(ip, "(%d+)") do
            table.insert(parts, part)
        end
        if #parts == 4 then
            return string.format("%s.%s.%s.%s.in-addr.arpa", parts[4], parts[3], parts[2], parts[1])
        end
    elseif is_valid_ipv6(ip) then
        -- IPv6: expand, reverse nibbles, append .ip6.arpa
        -- This is complex, so for IPv6 PTR we'll fall back to local tools
        -- Full IPv6 expansion requires handling :: compression properly
        return nil
    end
    
    return nil
end

-- Query Cloudflare DNS over HTTPS (DoH) API
local function cloudflare_doh_query(name, record_type)
    record_type = record_type or "A"
    
    if not name or name == "" then
        return nil, "Query name is required"
    end
    
    -- Cloudflare DoH endpoint
    local doh_url = "https://cloudflare-dns.com/dns-query"
    
    -- URL encode the name parameter (basic encoding for common cases)
    local encoded_name = string.gsub(name, "([^%w%-%.])", function(c)
        return string.format("%%%02X", string.byte(c))
    end)
    
    -- Build query URL with parameters
    local query_url = string.format("%s?name=%s&type=%s", doh_url, encoded_name, record_type)
    
    -- Set headers for JSON response
    local headers = {
        ["Accept"] = "application/dns-json"
    }
    
    log_message("Querying Cloudflare DoH for: " .. name .. " (type: " .. record_type .. ")")
    
    -- Make HTTP GET request
    local response, err = http_get(query_url, headers)
    if err then
        return nil, "Cloudflare DoH query failed: " .. err
    end
    
    if not response or response == "" then
        return nil, "Empty response from Cloudflare DoH"
    end
    
    -- Parse JSON response
    local json_data = parse_json(response)
    if not json_data then
        return nil, "Failed to parse Cloudflare DoH JSON response"
    end
    
    -- Check for errors in response
    if json_data.Status and json_data.Status ~= 0 then
        local error_msg = json_data.Comment or ("DNS query failed with status: " .. tostring(json_data.Status))
        -- Status 3 = NXDOMAIN (domain not found) - this is not an error, just no records
        if json_data.Status == 3 then
            return {
                name = name,
                type = record_type,
                records = {},
                status = json_data.Status,
                comment = error_msg
            }, nil
        end
        return nil, error_msg
    end
    
    -- Extract answer records
    local records = {}
    if json_data.Answer and type(json_data.Answer) == "table" then
        for _, answer in ipairs(json_data.Answer) do
            if answer.type and answer.data then
                -- Map DNS type numbers to names (common ones)
                local type_map = {
                    [1] = "A",
                    [28] = "AAAA",
                    [5] = "CNAME",
                    [15] = "MX",
                    [2] = "NS",
                    [16] = "TXT",
                    [6] = "SOA",
                    [12] = "PTR"
                }
                local answer_type = type_map[answer.type] or tostring(answer.type)
                
                -- Extract data based on record type
                local record_data = answer.data
                
                -- For MX records, data format is "priority domain"
                if answer_type == "MX" then
                    -- Keep full MX record (priority + domain)
                    table.insert(records, record_data)
                -- For SOA records, data is complex, keep as-is
                elseif answer_type == "SOA" then
                    table.insert(records, record_data)
                -- For PTR, CNAME, NS - data is domain name
                elseif answer_type == "PTR" or answer_type == "CNAME" or answer_type == "NS" then
                    -- Remove trailing dot if present
                    record_data = string.gsub(record_data, "%.$", "")
                    table.insert(records, record_data)
                -- For TXT records, data may be quoted
                elseif answer_type == "TXT" then
                    -- Remove quotes if present
                    record_data = string.gsub(record_data, '^"(.*)"$', "%1")
                    table.insert(records, record_data)
                -- For A and AAAA, data is IP address
                else
                    table.insert(records, record_data)
                end
            end
        end
    end
    
    return {
        name = name,
        type = record_type,
        records = records,
        status = json_data.Status or 0,
        tc = json_data.TC or false,  -- Truncated flag
        rd = json_data.RD or false,  -- Recursion desired
        ra = json_data.RA or false,  -- Recursion available
        ad = json_data.AD or false,  -- Authenticated data
        cd = json_data.CD or false   -- Checking disabled
    }, nil
end

-- Check which DNS tool is available (dig or nslookup)
local function check_dns_tool_available()
    local is_windows = package.config:sub(1,1) == "\\"
    local dig_available = false
    local nslookup_available = false
    
    -- Check for dig
    if is_windows then
        local dig_result = execute_silent("where dig.exe 2>&1")
        if dig_result and dig_result ~= "" and not string.find(dig_result:lower(), "not found") and not string.find(dig_result:lower(), "could not find") then
            dig_available = true
        end
        if not dig_available then
            dig_result = execute_silent("where dig 2>&1")
            if dig_result and dig_result ~= "" and not string.find(dig_result:lower(), "not found") and not string.find(dig_result:lower(), "could not find") then
                dig_available = true
            end
        end
    else
        local dig_check = io.popen("which dig 2>&1")
        if dig_check then
            local dig_result = dig_check:read("*a")
            dig_check:close()
            if dig_result and dig_result ~= "" and not string.find(dig_result:lower(), "not found") then
                dig_available = true
            end
        end
    end
    
    -- Check for nslookup (especially useful on Windows)
    if is_windows then
        local nslookup_result = execute_silent("where nslookup.exe 2>&1")
        if nslookup_result and nslookup_result ~= "" and not string.find(nslookup_result:lower(), "not found") and not string.find(nslookup_result:lower(), "could not find") then
            nslookup_available = true
        end
        if not nslookup_available then
            nslookup_result = execute_silent("where nslookup 2>&1")
            if nslookup_result and nslookup_result ~= "" and not string.find(nslookup_result:lower(), "not found") and not string.find(nslookup_result:lower(), "could not find") then
                nslookup_available = true
            end
        end
    else
        local nslookup_check = io.popen("which nslookup 2>&1")
        if nslookup_check then
            local nslookup_result = nslookup_check:read("*a")
            nslookup_check:close()
            if nslookup_result and nslookup_result ~= "" and not string.find(nslookup_result:lower(), "not found") then
                nslookup_available = true
            end
        end
    end
    
    return dig_available, nslookup_available
end

-- Parse nslookup output for reverse DNS (PTR)
local function parse_nslookup_ptr(output)
    local domains = {}
    -- nslookup -type=PTR returns lines like:
    -- Name: example.com
    -- or just the domain name on some systems
    for line in string.gmatch(output, "([^\r\n]+)") do
        line = string.gsub(line, "^%s+", "")
        line = string.gsub(line, "%s+$", "")
        -- Extract domain from "Name: domain.com" format
        local domain = string.match(line, "^[Nn]ame:%s*(.+)")
        if not domain then
            -- Try to match just a domain name (if it looks like a domain)
            if string.find(line, "%.") and not string.find(line:lower(), "server") and 
               not string.find(line:lower(), "address") and not string.find(line:lower(), "can't find") and
               not string.find(line:lower(), "non-existent") and not string.find(line:lower(), "error") then
                domain = line
            end
        end
        if domain then
            domain = string.gsub(domain, "%.$", "")  -- Remove trailing dot
            if domain ~= "" and domain ~= "Name" then
                table.insert(domains, domain)
            end
        end
    end
    return domains
end

-- Parse nslookup output for forward DNS records
local function parse_nslookup_forward(output, record_type)
    local records = {}
    -- nslookup output format varies by record type
    -- For A records: "Address: 1.2.3.4" or "Addresses: 1.2.3.4, 2.3.4.5"
    -- For MX: "mail exchanger = 10 mail.example.com"
    -- For NS: "nameserver = ns.example.com"
    -- For TXT: "text = "value""
    
    for line in string.gmatch(output, "([^\r\n]+)") do
        line = string.gsub(line, "^%s+", "")
        line = string.gsub(line, "%s+$", "")
        
        -- Skip header lines
        if string.find(line:lower(), "server") or string.find(line:lower(), "can't find") or
           string.find(line:lower(), "non-existent") or string.find(line:lower(), "***") then
            -- Skip
        elseif record_type == "A" or record_type == "AAAA" then
            -- Extract IP addresses
            local addr = string.match(line, "^[Aa]ddress(es)?:%s*(.+)")
            if addr then
                -- Handle multiple addresses separated by commas
                for ip in string.gmatch(addr, "([%d%.:a-fA-F]+)") do
                    if is_valid_ip(ip) then
                        table.insert(records, ip)
                    end
                end
            elseif is_valid_ip(line) then
                table.insert(records, line)
            end
        elseif record_type == "MX" then
            -- Extract mail exchanger: "mail exchanger = 10 mail.example.com"
            local mx = string.match(line, "mail%s+exchanger%s*=%s*(.+)")
            if mx then
                mx = string.gsub(mx, "^%s+", "")
                mx = string.gsub(mx, "%s+$", "")
                table.insert(records, mx)
            end
        elseif record_type == "NS" then
            -- Extract nameserver: "nameserver = ns.example.com"
            local ns = string.match(line, "nameserver%s*=%s*(.+)")
            if ns then
                ns = string.gsub(ns, "^%s+", "")
                ns = string.gsub(ns, "%s+$", "")
                ns = string.gsub(ns, "%.$", "")
                table.insert(records, ns)
            end
        elseif record_type == "TXT" then
            -- Extract text: 'text = "value"'
            local txt = string.match(line, 'text%s*=%s*"([^"]+)"')
            if txt then
                table.insert(records, txt)
            end
        elseif record_type == "SOA" then
            -- SOA records are complex, extract the whole line if it contains domain info
            if string.find(line, "%.") and not string.find(line:lower(), "server") then
                table.insert(records, line)
            end
        elseif record_type == "CNAME" then
            -- CNAME: "canonical name = example.com"
            local cname = string.match(line, "canonical%s+name%s*=%s*(.+)")
            if cname then
                cname = string.gsub(cname, "^%s+", "")
                cname = string.gsub(cname, "%s+$", "")
                cname = string.gsub(cname, "%.$", "")
                table.insert(records, cname)
            end
        end
    end
    
    return records
end

-- Perform reverse DNS lookup (PTR record) to get domain name from IP
local function reverse_dns_lookup(ip)
    if not is_valid_ip(ip) then
        return nil, "Invalid IP address"
    end
    
    -- Check cache first
    local cached = cache_get("reverse_dns", ip)
    if cached then
        log_message("Using cached reverse DNS data for IP: " .. ip)
        return cached, nil
    end
    
    -- Try Cloudflare DoH first (works cross-platform, no local tools needed)
    if ensure_curl_checked() then
        local reverse_name = ip_to_reverse_dns(ip)
        if reverse_name then
            log_message("Attempting Cloudflare DoH reverse DNS lookup for IP: " .. ip)
            local doh_result, doh_err = cloudflare_doh_query(reverse_name, "PTR")
            if not doh_err and doh_result and doh_result.records and #doh_result.records > 0 then
                local result = {
                    ip = ip,
                    ptr_records = doh_result.records,
                    primary_domain = doh_result.records[1]  -- Use first domain as primary
                }
                -- Cache the result
                cache_set("reverse_dns", ip, result)
                log_message("Cloudflare DoH reverse DNS lookup successful")
                return result, nil
            elseif doh_err then
                log_message("Cloudflare DoH reverse DNS lookup failed: " .. doh_err .. " (falling back to local tools)")
            end
        elseif is_valid_ipv6(ip) then
            log_message("IPv6 reverse DNS via Cloudflare DoH not yet supported, falling back to local tools")
        end
    end
    
    -- Fallback to local DNS tools if Cloudflare DoH failed or unavailable
    -- Check which DNS tool is available
    local dig_available, nslookup_available = check_dns_tool_available()
    
    if not dig_available and not nslookup_available then
        return nil, "No DNS lookup tool found. Please install 'dig' (BIND tools) or ensure 'nslookup' is available. Cloudflare DoH also requires curl."
    end
    
    local cmd
    local use_nslookup = not dig_available
    
    if use_nslookup then
        -- Use nslookup for reverse DNS
        cmd = string.format("nslookup -type=PTR %s 2>&1", ip)
    else
        -- Use dig for reverse DNS lookup (preferred, more reliable)
        if is_valid_ipv4(ip) then
            cmd = string.format("dig +short -x %s 2>&1", ip)
        else
            -- IPv6: dig can handle IPv6 directly with -x
            cmd = string.format("dig +short -x %s 2>&1", ip)
        end
    end
    
    log_message("Performing reverse DNS lookup for IP: " .. ip)
    log_message("Using tool: " .. (use_nslookup and "nslookup" or "dig"))
    log_message("Command: " .. cmd)
    
    -- Use silent execution on Windows to suppress command windows
    local output = execute_silent(cmd)
    if not output then
        return nil, "Failed to execute DNS lookup command."
    end
    
    -- Check for common error messages
    if output and (string.find(output:lower(), "not recognized") or 
                   string.find(output:lower(), "not found") or
                   string.find(output:lower(), "command not found") or
                   string.find(output:lower(), "could not find")) then
        return nil, "DNS lookup tool not found. Please install 'dig' (BIND tools) or ensure 'nslookup' is available."
    end
    
    if not output or output == "" then
        return nil, "No reverse DNS record found for IP: " .. ip
    end
    
    -- Parse output based on tool used
    local domains = {}
    if use_nslookup then
        domains = parse_nslookup_ptr(output)
    else
        -- Parse dig output - dig returns domain name(s), one per line
        for line in string.gmatch(output, "([^\r\n]+)") do
            line = string.gsub(line, "^%s+", "")  -- Trim leading whitespace
            line = string.gsub(line, "%s+$", "")  -- Trim trailing whitespace
            -- Remove trailing dot if present
            line = string.gsub(line, "%.$", "")
            -- Skip error messages
            if line ~= "" and 
               not string.find(line:lower(), "failed") and 
               not string.find(line:lower(), "error") and
               not string.find(line:lower(), "not recognized") and
               not string.find(line:lower(), "not found") and
               not string.find(line:lower(), "command not found") then
                table.insert(domains, line)
            end
        end
    end
    
    if #domains == 0 then
        return nil, "No valid reverse DNS record found for IP: " .. ip
    end
    
    local result = {
        ip = ip,
        ptr_records = domains,
        primary_domain = domains[1]  -- Use first domain as primary
    }
    
    -- Cache the result
    cache_set("reverse_dns", ip, result)
    
    return result, nil
end

-- Perform DNS lookup for specific record type
local function dns_lookup(domain, record_type)
    record_type = record_type or "A"
    
    if not domain or domain == "" then
        return nil, "Domain name required"
    end
    
    -- Check cache
    local cache_key = "dns_" .. record_type .. "_" .. domain
    local cached = cache_get("dns_lookup", cache_key)
    if cached then
        log_message("Using cached DNS " .. record_type .. " record for: " .. domain)
        return cached, nil
    end
    
    -- Try Cloudflare DoH first (works cross-platform, no local tools needed)
    if ensure_curl_checked() then
        log_message("Attempting Cloudflare DoH DNS lookup for: " .. domain .. " (type: " .. record_type .. ")")
        local doh_result, doh_err = cloudflare_doh_query(domain, record_type)
        if not doh_err and doh_result then
            -- Even if no records, return the result structure
            local result = {
                domain = domain,
                record_type = record_type,
                records = doh_result.records or {}
            }
            -- Cache the result
            cache_set("dns_lookup", cache_key, result)
            log_message("Cloudflare DoH DNS lookup successful")
            return result, nil
        elseif doh_err then
            log_message("Cloudflare DoH DNS lookup failed: " .. doh_err .. " (falling back to local tools)")
        end
    end
    
    -- Fallback to local DNS tools if Cloudflare DoH failed or unavailable
    -- Check which DNS tool is available
    local dig_available, nslookup_available = check_dns_tool_available()
    
    if not dig_available and not nslookup_available then
        return nil, "No DNS lookup tool found. Please install 'dig' (BIND tools) or ensure 'nslookup' is available. Cloudflare DoH also requires curl."
    end
    
    local cmd
    local use_nslookup = not dig_available
    
    if use_nslookup then
        -- Use nslookup for DNS lookup
        cmd = string.format("nslookup -type=%s %s 2>&1", record_type, domain)
    else
        -- Use dig for DNS lookup (preferred)
        cmd = string.format("dig +short %s %s 2>&1", domain, record_type)
    end
    
    log_message("DNS lookup: " .. record_type .. " record for " .. domain)
    log_message("Using tool: " .. (use_nslookup and "nslookup" or "dig"))
    
    -- Use silent execution on Windows to suppress command windows
    local output = execute_silent(cmd)
    if not output then
        return nil, "Failed to execute DNS lookup command"
    end
    
    -- Check for common error messages
    if output and (string.find(output:lower(), "not recognized") or 
                   string.find(output:lower(), "not found") or
                   string.find(output:lower(), "command not found") or
                   string.find(output:lower(), "could not find")) then
        return nil, "DNS lookup tool not found. Please install 'dig' (BIND tools) or ensure 'nslookup' is available."
    end
    
    -- Initialize records as empty table
    local records = {}
    
    if output and output ~= "" then
        if use_nslookup then
            -- Parse nslookup output
            records = parse_nslookup_forward(output, record_type)
        else
            -- Parse dig output
            for line in string.gmatch(output, "([^\r\n]+)") do
                line = string.gsub(line, "^%s+", "")
                line = string.gsub(line, "%s+$", "")
                line = string.gsub(line, "%.$", "")  -- Remove trailing dot
                -- Skip error messages
                if line ~= "" and 
                   not string.find(line:lower(), "failed") and 
                   not string.find(line:lower(), "error") and
                   not string.find(line:lower(), "not recognized") and
                   not string.find(line:lower(), "not found") and
                   not string.find(line:lower(), "command not found") then
                    table.insert(records, line)
                end
            end
        end
    end
    
    -- Always return a result with records table (even if empty)
    local result = {
        domain = domain,
        record_type = record_type,
        records = records
    }
    
    -- Cache the result
    cache_set("dns_lookup", cache_key, result)
    
    return result, nil
end

-- Perform comprehensive DNS analytics for an IP address
local function lookup_dns_analytics(ip)
    if not is_valid_ip(ip) then
        return nil, "Invalid IP address"
    end
    
    -- Check cache first
    local cached = cache_get("dns_analytics", ip)
    if cached then
        log_message("Using cached DNS analytics data for IP: " .. ip)
        return cached, nil
    end
    
    local result = {
        ip = ip,
        reverse_dns = nil,
        forward_dns = {},
        registration_info = nil,
        ip_registration_info = nil,
        forward_domain = nil,
        forward_domain_source = nil,
        candidate_domains = {}
    }

    local function add_candidate(source, domain)
        if not domain or domain == "" then return end
        for _, c in ipairs(result.candidate_domains) do
            if c.domain == domain then return end
        end
        table.insert(result.candidate_domains, { source = source, domain = domain })
    end
    
    -- Step 1: Reverse DNS lookup (PTR)
    log_message("Step 1: Performing reverse DNS lookup for IP: " .. ip)
    local ptr_data, ptr_err = reverse_dns_lookup(ip)
    if ptr_err then
        log_message("Reverse DNS lookup failed: " .. ptr_err)
        result.reverse_dns_error = ptr_err
    else
        result.reverse_dns = ptr_data
        if ptr_data.primary_domain then
            add_candidate("PTR", ptr_data.primary_domain)
        end
        if ptr_data.ptr_records then
            for _, ptr in ipairs(ptr_data.ptr_records) do
                add_candidate("PTR", ptr)
            end
        end
    end
    
    -- Step 2: Determine a domain for forward DNS
    local forward_domain = nil
    local forward_domain_source = nil
    if ptr_data and ptr_data.primary_domain then
        forward_domain = ptr_data.primary_domain
        forward_domain_source = "PTR"
    end

    -- Fallback: use IPinfo hostname if PTR is missing
    if CONFIG.IPINFO_ENABLED and CONFIG.IPINFO_API_KEY ~= "" then
        local ipinfo_data, ipinfo_err = lookup_ipinfo_ip(ip)
        if not ipinfo_err and ipinfo_data and ipinfo_data.hostname and ipinfo_data.hostname ~= "" then
            add_candidate("IPinfo", ipinfo_data.hostname)
        end
    end

    -- Fallback: use Shodan hostnames if PTR/IPinfo missing
    if CONFIG.SHODAN_ENABLED and CONFIG.SHODAN_API_KEY ~= "" then
        local shodan_data, shodan_err = lookup_shodan_ip(ip)
        if not shodan_err and shodan_data and shodan_data.hostnames and #shodan_data.hostnames > 0 then
            for _, h in ipairs(shodan_data.hostnames) do
                add_candidate("Shodan", h)
            end
        end
    end

    if not forward_domain and #result.candidate_domains > 0 then
        forward_domain = result.candidate_domains[1].domain
        forward_domain_source = result.candidate_domains[1].source
    end

    if forward_domain then
        result.forward_domain = forward_domain
        result.forward_domain_source = forward_domain_source
        log_message("Step 2: Performing forward DNS lookups for domain: " .. forward_domain .. " (source: " .. forward_domain_source .. ")")

        local record_types = {"A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"}
        for _, rtype in ipairs(record_types) do
            local dns_data, dns_err = dns_lookup(forward_domain, rtype)
            if not dns_err and dns_data and dns_data.records and type(dns_data.records) == "table" and #dns_data.records > 0 then
                result.forward_dns[rtype] = dns_data.records
            end
        end

        -- Step 3: Get registration info from RDAP
        if CONFIG.RDAP_ENABLED then
            log_message("Step 3: Getting registration info from RDAP for domain: " .. forward_domain)
            local rdap_data, rdap_err = lookup_domain_rdap(forward_domain)
            if not rdap_err and rdap_data then
                result.registration_info = rdap_data
            end
        end
    end

    -- Step 4: IP registration info (RDAP) regardless of PTR
    if CONFIG.RDAP_ENABLED then
        log_message("Step 4: Getting IP registration info from RDAP for IP: " .. ip)
        local ip_rdap_data, ip_rdap_err = lookup_ip_rdap(ip)
        if not ip_rdap_err and ip_rdap_data then
            result.ip_registration_info = ip_rdap_data
        else
            log_message("IP RDAP lookup failed: " .. tostring(ip_rdap_err))
        end
    end
    
    -- Cache the result
    cache_set("dns_analytics", ip, result)
    
    return result, nil
end

-- Format DNS analytics results
local function format_dns_analytics_result(data, ip)
    ip = ip or "unknown"
    
    if not data then
        return "=== DNS Analytics ===\n\n" ..
               "IP Address: " .. ip .. "\n\n" ..
               "No DNS analytics data available."
    end
    
    local result = "=== DNS Analytics ===\n\n"
    result = result .. "IP Address: " .. (data.ip or ip) .. "\n"
    result = result .. "ASK Build: " .. ASK_BUILD .. "\n\n"
    
    -- Reverse DNS (PTR Records)
    result = result .. "--- Reverse DNS (PTR Records) ---\n"
    if data.reverse_dns_error then
        -- Check if error indicates DNS tool is not available
        if string.find(data.reverse_dns_error:lower(), "not found") or 
           string.find(data.reverse_dns_error:lower(), "not recognized") or
           string.find(data.reverse_dns_error:lower(), "command not found") then
            result = result .. "ERROR: DNS lookup tool not available\n"
            result = result .. "\nDNS Analytics can use:\n"
            result = result .. "  - Cloudflare DNS over HTTPS (requires curl)\n"
            result = result .. "  - Local tools: 'dig' or 'nslookup'\n"
            result = result .. "On Windows, 'nslookup' should be available by default.\n"
            result = result .. "Please install curl or a DNS tool and restart Wireshark.\n"
        else
            result = result .. "Error: " .. data.reverse_dns_error .. "\n"
        end
    elseif data.reverse_dns and data.reverse_dns.ptr_records then
        for i, ptr in ipairs(data.reverse_dns.ptr_records) do
            result = result .. "PTR " .. i .. ": " .. ptr .. "\n"
        end
        if data.reverse_dns.primary_domain then
            result = result .. "\nPrimary Domain: " .. data.reverse_dns.primary_domain .. "\n"
        end
    else
        result = result .. "No PTR record found\n"
    end

    -- FQDN Candidates
    result = result .. "\n--- FQDN Candidates ---\n"
    if data.candidate_domains and #data.candidate_domains > 0 then
        for i, c in ipairs(data.candidate_domains) do
            result = result .. string.format("%d. %s (source: %s)\n", i, c.domain, c.source)
        end
    else
        result = result .. "None (PTR/IPinfo/Shodan did not provide a hostname)\n"
        local hints = {}
        if not (data.reverse_dns and data.reverse_dns.primary_domain) then
            table.insert(hints, "PTR missing")
        end
        if not CONFIG.IPINFO_API_KEY or CONFIG.IPINFO_API_KEY == "" then
            table.insert(hints, "IPinfo key not configured")
        end
        if not CONFIG.SHODAN_API_KEY or CONFIG.SHODAN_API_KEY == "" then
            table.insert(hints, "Shodan key not configured")
        end
        if #hints > 0 then
            result = result .. "Hints: " .. table.concat(hints, "; ") .. "\n"
        end
    end
    
    -- Forward DNS Records
    if data.reverse_dns_error and (string.find(data.reverse_dns_error:lower(), "not found") or 
                                    string.find(data.reverse_dns_error:lower(), "not recognized") or
                                    string.find(data.reverse_dns_error:lower(), "command not found")) then
        -- Skip forward DNS if DNS tool is not available
        result = result .. "\n--- Forward DNS Records ---\n"
        result = result .. "Cannot perform forward DNS lookups: DNS lookup tool not available\n"
        result = result .. "DNS Analytics can use Cloudflare DoH (requires curl) or local tools (dig/nslookup).\n"
    elseif data.forward_dns and next(data.forward_dns) then
        local src_note = ""
        if data.forward_domain and data.forward_domain_source then
            src_note = string.format(" (domain: %s, source: %s)", data.forward_domain, data.forward_domain_source)
        end
        result = result .. "\n--- Forward DNS Records" .. src_note .. " ---\n"
        
        -- A Records (IPv4)
        if data.forward_dns.A and #data.forward_dns.A > 0 then
            result = result .. "\nA Records (IPv4):\n"
            for i, record in ipairs(data.forward_dns.A) do
                result = result .. "  " .. i .. ". " .. record .. "\n"
            end
        end
        
        -- AAAA Records (IPv6)
        if data.forward_dns.AAAA and #data.forward_dns.AAAA > 0 then
            result = result .. "\nAAAA Records (IPv6):\n"
            for i, record in ipairs(data.forward_dns.AAAA) do
                result = result .. "  " .. i .. ". " .. record .. "\n"
            end
        end
        
        -- MX Records (Mail Exchange)
        if data.forward_dns.MX and #data.forward_dns.MX > 0 then
            result = result .. "\nMX Records (Mail Exchange):\n"
            for i, record in ipairs(data.forward_dns.MX) do
                -- MX records format: "priority hostname" or just "hostname"
                -- Parse priority if present
                local priority, hostname = string.match(record, "^(%d+)%s+(.+)$")
                if priority and hostname then
                    result = result .. "  " .. i .. ". Priority: " .. priority .. " → " .. hostname .. "\n"
                else
                    result = result .. "  " .. i .. ". " .. record .. "\n"
                end
            end
        end
        
        -- NS Records (Name Servers)
        if data.forward_dns.NS and #data.forward_dns.NS > 0 then
            result = result .. "\nNS Records (Name Servers):\n"
            for i, record in ipairs(data.forward_dns.NS) do
                result = result .. "  " .. i .. ". " .. record .. "\n"
            end
        end
        
        -- TXT Records
        if data.forward_dns.TXT and #data.forward_dns.TXT > 0 then
            result = result .. "\nTXT Records:\n"
            for i, record in ipairs(data.forward_dns.TXT) do
                -- Truncate very long TXT records
                local display_record = record
                if string.len(display_record) > 100 then
                    display_record = string.sub(display_record, 1, 100) .. "..."
                end
                result = result .. "  " .. i .. ". " .. display_record .. "\n"
            end
        end
        
        -- SOA Record (Start of Authority)
        if data.forward_dns.SOA and #data.forward_dns.SOA > 0 then
            result = result .. "\nSOA Record (Start of Authority):\n"
            local soa_record = data.forward_dns.SOA[1]
            -- SOA format: "ns.example.com. admin.example.com. serial refresh retry expire minimum"
            -- Try to parse and format nicely
            local parts = {}
            for part in string.gmatch(soa_record, "([^%s]+)") do
                -- Remove trailing dots
                part = string.gsub(part, "%.$", "")
                table.insert(parts, part)
            end
            
            if #parts >= 7 then
                result = result .. "  Primary Name Server: " .. parts[1] .. "\n"
                result = result .. "  Responsible Email: " .. parts[2] .. "\n"
                result = result .. "  Serial Number: " .. parts[3] .. "\n"
                result = result .. "  Refresh: " .. parts[4] .. " seconds\n"
                result = result .. "  Retry: " .. parts[5] .. " seconds\n"
                result = result .. "  Expire: " .. parts[6] .. " seconds\n"
                result = result .. "  Minimum TTL: " .. parts[7] .. " seconds\n"
            else
                -- Fallback: show raw record
                result = result .. "  " .. soa_record .. "\n"
            end
        end
        
        -- CNAME Records
        if data.forward_dns.CNAME and #data.forward_dns.CNAME > 0 then
            result = result .. "\nCNAME Records:\n"
            for i, record in ipairs(data.forward_dns.CNAME) do
                result = result .. "  " .. i .. ". " .. record .. "\n"
            end
        end
    else
        result = result .. "\n--- Forward DNS Records ---\n"
        if data.reverse_dns and data.reverse_dns.primary_domain then
            result = result .. "No forward DNS records found for: " .. data.reverse_dns.primary_domain .. "\n"
        else
        if data.forward_domain and data.forward_domain_source then
            result = result .. "No forward DNS records available (domain: " .. data.forward_domain .. ", source: " .. data.forward_domain_source .. ")\n"
        else
            result = result .. "No forward DNS records available (no PTR record found)\n"
        end
        end

    -- IP Registration (RDAP) - available even without PTR
    result = result .. "\n--- IP Registration (RDAP) ---\n"
    if data.ip_registration_info then
        local ipr = data.ip_registration_info
        if ipr._detected_rir then
            result = result .. "Registry: " .. ipr._detected_rir .. "\n"
        end
        if ipr.startAddress and ipr.endAddress then
            result = result .. "Range: " .. ipr.startAddress .. " - " .. ipr.endAddress .. "\n"
        end
        if ipr.cidr0_cidrs and ipr.cidr0_cidrs[1] then
            local cidr = ipr.cidr0_cidrs[1].v4prefix or ipr.cidr0_cidrs[1].v6prefix
            if cidr then result = result .. "CIDR: " .. cidr .. "\n" end
        elseif ipr.cidr then
            result = result .. "CIDR: " .. ipr.cidr .. "\n"
        end
        if ipr.country then
            result = result .. "Country: " .. ipr.country .. "\n"
        end
        if ipr.name then
            result = result .. "Network Name: " .. ipr.name .. "\n"
        end
        if ipr.handle then
            result = result .. "Handle: " .. ipr.handle .. "\n"
        end
        if ipr.type then
            result = result .. "Type: " .. ipr.type .. "\n"
        elseif ipr.netType then
            result = result .. "Net Type: " .. ipr.netType .. "\n"
        end
    else
        result = result .. "IP registration info not available\n"
    end
    end
    
    -- Registration Information (RDAP)
    if data.reverse_dns_error and (string.find(data.reverse_dns_error:lower(), "not found") or 
                                    string.find(data.reverse_dns_error:lower(), "not recognized") or
                                    string.find(data.reverse_dns_error:lower(), "command not found")) then
        -- Skip registration info if DNS tool failed
        result = result .. "\n--- Domain Registration Information ---\n"
        result = result .. "Cannot retrieve registration info: DNS lookup tool not available\n"
    elseif data.registration_info then
        result = result .. "\n--- Domain Registration Information (RDAP) ---\n"
        
        -- Extract registration date and calculate domain age
        local registration_date = nil
        local domain_age_days = nil
        
        if data.registration_info.events then
            for _, event in ipairs(data.registration_info.events) do
                if event.eventAction == "registration" and event.eventDate then
                    registration_date = event.eventDate
                    result = result .. "Registration Date: " .. event.eventDate .. "\n"
                end
                if event.eventAction == "last changed" and event.eventDate then
                    result = result .. "Last Changed: " .. event.eventDate .. "\n"
                end
            end
        end
        
        -- Calculate and display domain age
        if registration_date then
            -- Parse ISO 8601 date (e.g., "2017-02-24T13:34:51Z" or "2017-02-24")
            local year, month, day = string.match(registration_date, "(%d%d%d%d)%-(%d%d)%-(%d%d)")
            if year and month and day then
                local reg_time = os.time({
                    year = tonumber(year),
                    month = tonumber(month),
                    day = tonumber(day),
                    hour = 0,
                    min = 0,
                    sec = 0
                })
                local current_time = os.time()
                domain_age_days = math.floor((current_time - reg_time) / 86400) -- seconds to days
                
                if domain_age_days >= 0 then
                    if domain_age_days < 30 then
                        result = result .. "\n⚠ Domain Age: " .. domain_age_days .. " days (FRESHLY REGISTERED)\n"
                        result = result .. "⚠ WARNING: Very recently registered domain - exercise caution\n"
                    elseif domain_age_days < 90 then
                        result = result .. "\n⚠ Domain Age: " .. domain_age_days .. " days (RECENTLY REGISTERED)\n"
                        result = result .. "⚠ Note: Recently registered - evaluate with additional scrutiny\n"
                    elseif domain_age_days < 365 then
                        result = result .. "\nDomain Age: " .. domain_age_days .. " days (less than 1 year old)\n"
                    else
                        local years = math.floor(domain_age_days / 365)
                        local remaining_days = domain_age_days % 365
                        result = result .. "\nDomain Age: " .. years .. " year" .. (years > 1 and "s" or "") .. 
                                (remaining_days > 0 and (", " .. remaining_days .. " days") or "") .. " (established)\n"
                    end
                end
            end
        end
        
        -- Extract registrar
        if data.registration_info.entities then
            for _, entity in ipairs(data.registration_info.entities) do
                if entity.roles and #entity.roles > 0 then
                    for _, role in ipairs(entity.roles) do
                        if role == "registrar" then
                            if entity.vcardArray then
                                for _, vcard in ipairs(entity.vcardArray) do
                                    if type(vcard) == "table" and vcard[1] == "fn" then
                                        result = result .. "Registrar: " .. (vcard[3] or "N/A") .. "\n"
                                    end
                                end
                            end
                        end
                    end
                end
            end
        end
        
        -- Extract status
        if data.registration_info.status then
            result = result .. "\nDomain Status:\n"
            for _, status in ipairs(data.registration_info.status) do
                result = result .. "  • " .. status .. "\n"
            end
        end
    else
        result = result .. "\n--- Domain Registration Information ---\n"
        if data.forward_domain and data.forward_domain_source then
            result = result .. "Registration info not available (domain: " .. data.forward_domain .. ", source: " .. data.forward_domain_source .. ")\n"
        elseif data.reverse_dns and data.reverse_dns.primary_domain then
            result = result .. "Registration info not available for: " .. data.reverse_dns.primary_domain .. "\n"
        else
            result = result .. "Registration info not available (no domain found)\n"
        end
    end
    
    result = result .. "\n--- Analysis Notes ---\n"
    result = result .. "• PTR records show the reverse DNS mapping (IP → Domain)\n"
    result = result .. "• Forward DNS records show how the domain resolves\n"
    result = result .. "• Registration dates help identify domain age\n"
    result = result .. "• Compare A/AAAA records with the original IP for verification\n"
    
    return result
end

-- DNS Analytics callback for IP addresses
local function dns_analytics_callback(fieldname, ...)
    local fields = {...}
    local ip_raw = get_field_value(fieldname, "display", fields)
    
    if not ip_raw then
        show_error_window("DNS Analytics", "Could not extract IP address from packet")
        return
    end
    
    -- Extract IP address from the field value
    local ip = extract_ip_from_string(ip_raw)
    if not ip then
        show_error_window("DNS Analytics", "Could not extract valid IP address from: " .. ip_raw)
        return
    end
    
    -- Check which DNS tool is available
    local dig_available, nslookup_available = check_dns_tool_available()
    
    if not dig_available and not nslookup_available then
        local is_windows = package.config:sub(1,1) == "\\"
        local error_msg = "No DNS lookup tool found.\n\n" ..
                         "DNS analytics requires 'dig' or 'nslookup'.\n\n"
        if is_windows then
            error_msg = error_msg ..
                       "On Windows, 'nslookup' should be available by default.\n" ..
                       "If not found, you can install:\n" ..
                       "• BIND tools from https://www.isc.org/download/\n" ..
                       "• OR use Chocolatey: choco install bind-toolsonly\n" ..
                       "• OR use WSL (Windows Subsystem for Linux)\n"
        else
            error_msg = error_msg ..
                       "Installation:\n" ..
                       "• macOS: brew install bind (or use system dig/nslookup)\n" ..
                       "• Linux: sudo apt-get install dnsutils (Debian/Ubuntu)\n" ..
                       "         sudo yum install bind-utils (RHEL/CentOS)\n"
        end
        error_msg = error_msg .. "\nAfter installation, restart Wireshark."
        show_error_window("DNS Analytics Error", error_msg)
        return
    end
    
    local data, err = lookup_dns_analytics(ip)
    if err then
        show_error_window("DNS Analytics Error", "Error performing DNS analytics:\n" .. err)
        return
    end
    
    local formatted = format_dns_analytics_result(data, ip)
    show_result_window("DNS Analytics: " .. ip, formatted)
end

-------------------------------------------------
-- Certificate Transparency Module (crt.sh)
-------------------------------------------------

local function lookup_certificate_transparency(domain)
    if not is_valid_domain(domain) then
        return nil, "Invalid domain name"
    end
    
    -- Check cache first
    local cached = cache_get("crt", domain)
    if cached then
        log_message("Using cached Certificate Transparency data for domain: " .. domain)
        return cached, nil
    end
    
    -- crt.sh API - search for certificates
    -- Certificate Transparency (CT) logs are public records of all SSL/TLS certificates
    -- issued by Certificate Authorities. crt.sh provides a search interface to these logs.
    local url = string.format("%s/?q=%%25.%s&output=json", CONFIG.CRT_SH_URL, domain)
    log_message("Querying Certificate Transparency for domain: " .. domain)
    
    local response, err = http_get(url)
    if err then
        return nil, err
    end
    
    if not response or response == "" then
        return nil, "Certificate Transparency API returned empty response"
    end
    
    local data = parse_json(response)
    if not data then
        -- crt.sh might return empty array [] or error message
        if string.find(response, "^%s*%[%s*%]") then
            -- Empty array - no certificates found
            return {}, nil
        end
        return nil, "Failed to parse Certificate Transparency response.\n\n" ..
                   "Response preview: " .. string.sub(response or "", 1, 200)
    end
    
    -- Ensure data is a table
    if type(data) ~= "table" then
        log_message("Certificate Transparency: Response is not a table, type: " .. type(data))
        return {}, nil
    end
    
    -- Handle empty array
    if #data == 0 then
        return {}, nil
    end
    
    -- Validate that all entries are tables
    for i, cert in ipairs(data) do
        if type(cert) ~= "table" then
            log_message("Certificate Transparency: Entry #" .. tostring(i) .. " is not a table, type: " .. type(cert))
            -- Convert to table if possible, or skip
            if type(cert) == "string" or type(cert) == "number" then
                data[i] = {raw = cert}
            else
                data[i] = {}
            end
        end
    end
    
    -- Cache the result
    cache_set("crt", domain, data)
    
    return data, nil
end

local function format_cert_transparency_result(data, domain)
    domain = domain or "unknown"
    
    if not data then 
        return "=== Certificate Transparency (crt.sh) ===\n\n" ..
               "Query: " .. domain .. "\n\n" ..
               "No certificates found in Certificate Transparency logs.\n" ..
               "This could mean:\n" ..
               "- The domain has no SSL/TLS certificates\n" ..
               "- Certificates were issued before CT logs existed\n" ..
               "- The domain uses wildcard certificates"
    end
    
    local result = "=== Certificate Transparency (crt.sh) ===\n\n"
    result = result .. "--- What is Certificate Transparency? ---\n"
    result = result .. "Certificate Transparency (CT) logs are public, append-only records\n"
    result = result .. "of all SSL/TLS certificates issued by Certificate Authorities.\n\n"
    result = result .. "Use Cases:\n"
    result = result .. "• Discover all certificates issued for a domain\n"
    result = result .. "• Detect unauthorized or suspicious certificate issuance\n"
    result = result .. "• Find subdomains through certificate data\n"
    result = result .. "• Monitor certificate expiration dates\n"
    result = result .. "• Identify certificate issuers and serial numbers\n"
    result = result .. "• Security research and threat intelligence\n\n"
    result = result .. "--- Search Results ---\n"
    result = result .. "Query: " .. domain .. "\n\n"
    
    if type(data) == "table" and #data > 0 then
        result = result .. "Found " .. tostring(#data) .. " certificate(s) in CT logs\n\n"
        
        -- Show first 10 certificates
        local count = math.min(10, #data)
        for i = 1, count do
            local cert = data[i]
            
            -- Skip if cert is nil or not a table
            if cert and type(cert) == "table" then
                result = result .. "--- Certificate #" .. tostring(i) .. " ---\n"
                
                if cert.name_value then
                    result = result .. "Domain(s): " .. tostring(cert.name_value) .. "\n"
                end
                
                if cert.issuer_name then
                    result = result .. "Issuer: " .. tostring(cert.issuer_name) .. "\n"
                end
                
                if cert.not_before then
                    result = result .. "Valid From: " .. tostring(cert.not_before) .. "\n"
                end
                
                if cert.not_after then
                    result = result .. "Valid Until: " .. tostring(cert.not_after) .. "\n"
                    -- Check if expired
                    local expiry_date = cert.not_after
                    if expiry_date then
                        -- Simple check: if date contains year < current year, likely expired
                        local year = string.match(tostring(expiry_date), "(%d%d%d%d)")
                        if year and tonumber(year) < tonumber(os.date("%Y")) then
                            result = result .. "⚠ Status: EXPIRED\n"
                        end
                    end
                end
                
                if cert.serial_number then
                    result = result .. "Serial: " .. tostring(cert.serial_number) .. "\n"
                end
                
                if cert.id then
                    result = result .. "CT Log ID: " .. tostring(cert.id) .. "\n"
                end
                
                if cert.entry_timestamp then
                    result = result .. "Logged: " .. tostring(cert.entry_timestamp) .. "\n"
                end
                
                result = result .. "\n"
            else
                log_message("Certificate Transparency: Skipping invalid cert entry #" .. tostring(i) .. " (type: " .. type(cert) .. ")")
            end
        end
        
        if #data > 10 then
            result = result .. "... and " .. tostring(#data - 10) .. " more certificates\n"
        end
        
        result = result .. "\n--- Security Analysis ---\n"
        result = result .. "• Review certificates for suspicious issuers\n"
        result = result .. "• Check for expired certificates\n"
        result = result .. "• Verify certificate domains match expected subdomains\n"
        result = result .. "• Look for wildcard certificates (*.domain.com)\n"
        result = result .. "• Detect unauthorized certificate issuance\n"
        result = result .. "• Monitor for certificate changes over time\n\n"
        result = result .. "--- Additional Information ---\n"
        result = result .. "• CT logs help prevent certificate misissuance\n"
        result = result .. "• All publicly-trusted certificates are logged\n"
        result = result .. "• Browsers can detect certificates not in CT logs\n"
        result = result .. "• Useful for security monitoring and threat detection\n"
    else
        result = result .. "No certificates found for this domain in CT logs\n"
        result = result .. "\nThis could indicate:\n"
        result = result .. "- Domain uses no SSL/TLS certificates\n"
        result = result .. "- Certificates issued before CT logging (pre-2015)\n"
        result = result .. "- Private/internal certificates not logged\n"
    end
    
    return result
end

local function cert_transparency_callback(...)
    local fields = {...}
    local domain = get_field_value("dns.qry.name", "value", fields)
    
    if not domain then
        -- Try TLS SNI field
        domain = get_field_value("tls.handshake.extensions_server_name", "value", fields)
    end
    
    if not domain then
        show_error_window("Certificate Transparency Lookup", "Could not extract domain name from packet")
        return
    end
    
    local data, err = lookup_certificate_transparency(domain)
    if err then
        show_error_window("Certificate Transparency Error", "Error querying crt.sh:\n" .. err)
        return
    end
    
    local formatted = format_cert_transparency_result(data, domain)
    show_result_window("Certificate Transparency: " .. domain, formatted)
end

-------------------------------------------------
-- Email Analysis Module
-------------------------------------------------

local function lookup_email_reputation(email)
    if not is_valid_email(email) then
        return nil, "Invalid email address format"
    end
    
    local clean_email = extract_email(email)
    
    local result = "=== Email Analysis ===\n\n"
    result = result .. "Email Address: " .. clean_email .. "\n\n"
    
    -- Extract domain and local part for analysis
    local local_part, domain = string.match(clean_email, "([^@]+)@(.+)")
    
    if not domain then
        return nil, "Could not extract domain from email address"
    end
    
    result = result .. "--- Email Components ---\n"
    result = result .. "Local Part: " .. (local_part or "N/A") .. "\n"
    result = result .. "Domain: " .. domain .. "\n\n"
    
    -- Basic email security checks
    result = result .. "--- Security Analysis ---\n"
    
    -- Check for suspicious patterns in local part
    if local_part then
        if string.find(local_part, "noreply") or string.find(local_part, "no%-reply") then
            result = result .. "⚠ Local part contains 'noreply' - likely automated sender\n"
        end
        if string.find(local_part, "support") or string.find(local_part, "help") then
            result = result .. "ℹ Local part suggests support/help address\n"
        end
        if string.find(local_part, "admin") or string.find(local_part, "administrator") then
            result = result .. "⚠ Local part contains 'admin' - verify authenticity\n"
        end
        if string.len(local_part) > 50 then
            result = result .. "⚠ Unusually long local part - possible suspicious pattern\n"
        end
    end
    
    -- Domain analysis
    result = result .. "\n--- Domain Analysis ---\n"
    
    -- Check domain validity
    if is_valid_domain(domain) then
        result = result .. "✓ Domain format is valid\n"
    else
        result = result .. "⚠ Domain format appears invalid\n"
    end
    
    -- Lookup domain registration info (RDAP) - no API key needed
    if CONFIG.RDAP_ENABLED then
        local rdap_data, rdap_err = lookup_domain_rdap(domain)
        if not rdap_err and rdap_data then
            result = result .. "\n--- Domain Registration Info (RDAP) ---\n"
            if rdap_data.entities and #rdap_data.entities > 0 then
                local entity = rdap_data.entities[1]
                if entity.vcardArray then
                    for _, vcard in ipairs(entity.vcardArray) do
                        if type(vcard) == "table" and vcard[1] == "fn" then
                            result = result .. "Registrant: " .. (vcard[3] or "N/A") .. "\n"
                        end
                    end
                end
            end
            if rdap_data.events then
                local registration_date = nil
                for _, event in ipairs(rdap_data.events) do
                    if event.eventAction == "registration" and event.eventDate then
                        registration_date = event.eventDate
                        result = result .. "Registered: " .. event.eventDate .. "\n"
                    end
                end
                
                -- Calculate and display domain age
                if registration_date then
                    local year, month, day = string.match(registration_date, "(%d%d%d%d)%-(%d%d)%-(%d%d)")
                    if year and month and day then
                        local reg_time = os.time({
                            year = tonumber(year),
                            month = tonumber(month),
                            day = tonumber(day),
                            hour = 0,
                            min = 0,
                            sec = 0
                        })
                        local current_time = os.time()
                        local domain_age_days = math.floor((current_time - reg_time) / 86400)
                        
                        if domain_age_days >= 0 then
                            if domain_age_days < 30 then
                                result = result .. "⚠ Domain Age: " .. domain_age_days .. " days (FRESHLY REGISTERED)\n"
                                result = result .. "⚠ WARNING: Very recently registered domain - high risk indicator\n"
                            elseif domain_age_days < 90 then
                                result = result .. "⚠ Domain Age: " .. domain_age_days .. " days (RECENTLY REGISTERED)\n"
                                result = result .. "⚠ Note: Recently registered - exercise caution\n"
                            elseif domain_age_days < 365 then
                                result = result .. "Domain Age: " .. domain_age_days .. " days\n"
                            else
                                local years = math.floor(domain_age_days / 365)
                                result = result .. "Domain Age: " .. years .. " year" .. (years > 1 and "s" or "") .. "\n"
                            end
                        end
                    end
                end
            end
        end
    end
    
    -- Lookup domain reputation (VirusTotal) - optional, requires API key
    if CONFIG.VIRUSTOTAL_ENABLED and CONFIG.VIRUSTOTAL_API_KEY ~= "" then
        local vt_data, vt_err = lookup_virustotal_domain(domain)
        if not vt_err and vt_data then
            result = result .. "\n--- Domain Reputation (VirusTotal) ---\n"
            if vt_data.data and vt_data.data.attributes then
                local stats = vt_data.data.attributes.last_analysis_stats
                if stats then
                    result = result .. "Harmless: " .. tostring(stats.harmless or 0) .. "\n"
                    result = result .. "Malicious: " .. tostring(stats.malicious or 0) .. "\n"
                    result = result .. "Suspicious: " .. tostring(stats.suspicious or 0) .. "\n"
                    
                    if (stats.malicious or 0) > 0 then
                        result = result .. "⚠ WARNING: Domain has malicious reports\n"
                    elseif (stats.suspicious or 0) > 0 then
                        result = result .. "⚠ CAUTION: Domain has suspicious reports\n"
                    else
                        result = result .. "✓ No malicious or suspicious reports\n"
                    end
                end
                
                if vt_data.data.attributes.categories then
                    result = result .. "\nCategories: "
                    local cats = {}
                    for cat, _ in pairs(vt_data.data.attributes.categories) do
                        table.insert(cats, cat)
                    end
                    if #cats > 0 then
                        result = result .. table.concat(cats, ", ") .. "\n"
                    end
                end
            end
        end
    else
        result = result .. "\n--- Domain Reputation ---\n"
        result = result .. "VirusTotal API key not configured (optional)\n"
        result = result .. "Configure for domain reputation checking\n"
    end
    
    result = result .. "\n--- Security Recommendations ---\n"
    result = result .. "• Check Have I Been Pwned: https://haveibeenpwned.com/email/" .. url_encode(clean_email) .. "\n"
    result = result .. "• Verify sender reputation and domain age\n"
    result = result .. "• Check email headers for SPF/DKIM/DMARC records\n"
    result = result .. "• Verify domain registration information\n"
    result = result .. "• Check for typosquatting (similar domain names)\n"
    result = result .. "• Review email content for phishing indicators\n"
    
    return result, nil
end

-------------------------------------------------
-- Network Diagnostic Tools (Ping & Traceroute)
-------------------------------------------------

-- Check if ping command is available
local function check_ping_available()
    local cmd_check
    if package.config:sub(1,1) == "\\" then
        -- Windows
        cmd_check = "where ping 2>&1"
    else
        -- Unix-like
        cmd_check = "which ping 2>&1"
    end
    
    local handle = io.popen(cmd_check)
    if not handle then
        return false, nil
    end
    
    local output = handle:read("*a")
    handle:close()
    
    if output and output ~= "" and not string.find(output, "not found") and not string.find(output, "No such") then
        return true, string.gsub(output, "%s+", "")
    end
    
    return false, nil
end

-- Check if traceroute/tracert command is available
local function check_traceroute_available()
    local cmd_check
    local cmd_name
    if package.config:sub(1,1) == "\\" then
        -- Windows uses tracert
        cmd_check = "where tracert 2>&1"
        cmd_name = "tracert"
    else
        -- Unix-like uses traceroute
        cmd_check = "which traceroute 2>&1"
        cmd_name = "traceroute"
    end
    
    local handle = io.popen(cmd_check)
    if not handle then
        return false, nil, nil
    end
    
    local output = handle:read("*a")
    handle:close()
    
    if output and output ~= "" and not string.find(output, "not found") and not string.find(output, "No such") then
        return true, string.gsub(output, "%s+", ""), cmd_name
    end
    
    return false, nil, cmd_name
end

-- Execute ping command
local function ping_host(ip)
    local ping_available, ping_path = check_ping_available()
    if not ping_available then
        local platform = "unknown"
        local install_instructions = ""
        
        if package.config:sub(1,1) == "\\" then
            platform = "Windows"
            install_instructions = "\n\nPing is typically included with Windows.\n" ..
                                  "If ping is not available, check your system PATH.\n" ..
                                  "Ping should be located in C:\\Windows\\System32\\ping.exe"
        else
            local uname_handle = io.popen("uname -s 2>&1")
            if uname_handle then
                local uname_output = uname_handle:read("*a")
                uname_handle:close()
                if string.find(uname_output, "Darwin") then
                    platform = "macOS"
                    install_instructions = "\n\nPing is typically included with macOS.\n" ..
                                          "If ping is not available, install network utilities:\n" ..
                                          "brew install iputils"
                else
                    platform = "Linux"
                    install_instructions = "\n\nInstallation Instructions for Linux:\n" ..
                                          "Debian/Ubuntu: sudo apt-get install iputils-ping\n" ..
                                          "RedHat/CentOS: sudo yum install iputils\n" ..
                                          "Fedora: sudo dnf install iputils\n" ..
                                          "Arch: sudo pacman -S iputils"
                end
            end
        end
        
        return nil, "Ping command is not installed or not found in PATH.\n\n" ..
                   "Platform detected: " .. platform .. "\n" ..
                   install_instructions
    end
    
    -- Build ping command based on platform
    local cmd
    if package.config:sub(1,1) == "\\" then
        -- Windows: ping -n 4 <ip>
        cmd = string.format("ping -n 4 %s 2>&1", ip)
    else
        -- Unix-like: ping -c 4 <ip>
        cmd = string.format("ping -c 4 %s 2>&1", ip)
    end
    
    log_message("Executing ping to: " .. ip)
    
    local handle = io.popen(cmd)
    if not handle then
        return nil, "Failed to execute ping command."
    end
    
    local output = handle:read("*a")
    handle:close()
    
    if not output or output == "" then
        return nil, "No output from ping command."
    end
    
    return output, nil
end

-- Execute traceroute command
local function traceroute_host(ip)
    local traceroute_available, traceroute_path, cmd_name = check_traceroute_available()
    if not traceroute_available then
        local platform = "unknown"
        local install_instructions = ""
        
        if package.config:sub(1,1) == "\\" then
            platform = "Windows"
            install_instructions = "\n\nTracert is typically included with Windows.\n" ..
                                  "If tracert is not available, check your system PATH.\n" ..
                                  "Tracert should be located in C:\\Windows\\System32\\tracert.exe"
        else
            local uname_handle = io.popen("uname -s 2>&1")
            if uname_handle then
                local uname_output = uname_handle:read("*a")
                uname_handle:close()
                if string.find(uname_output, "Darwin") then
                    platform = "macOS"
                    install_instructions = "\n\nInstallation Instructions for macOS:\n" ..
                                          "brew install traceroute\n" ..
                                          "OR\n" ..
                                          "sudo port install traceroute"
                else
                    platform = "Linux"
                    install_instructions = "\n\nInstallation Instructions for Linux:\n" ..
                                          "Debian/Ubuntu: sudo apt-get install traceroute\n" ..
                                          "RedHat/CentOS: sudo yum install traceroute\n" ..
                                          "Fedora: sudo dnf install traceroute\n" ..
                                          "Arch: sudo pacman -S traceroute"
                end
            end
        end
        
        return nil, "Traceroute command is not installed or not found in PATH.\n\n" ..
                   "Platform detected: " .. platform .. "\n" ..
                   install_instructions
    end
    
    -- Build traceroute command with optimized settings for faster completion
    -- Reduced to 10 hops (most routes complete within 10 hops)
    -- Reduced timeout to 1 second per hop for faster failure detection
    local cmd
    if package.config:sub(1,1) == "\\" then
        -- Windows: tracert -h 10 -w 1000 <ip> (10 hops max, 1 second timeout per hop)
        cmd = string.format("tracert -h 10 -w 1000 %s 2>&1", ip)
    else
        -- Detect macOS vs Linux for timeout command availability
        local uname_handle = io.popen("uname -s 2>&1")
        local is_macos = false
        if uname_handle then
            local uname_output = uname_handle:read("*a")
            uname_handle:close()
            if string.find(uname_output, "Darwin") then
                is_macos = true
            end
        end
        
        if is_macos then
            -- macOS: traceroute -m 10 -w 1 <ip> (10 hops max, 1 second timeout per hop)
            cmd = string.format("traceroute -m 10 -w 1 %s 2>&1", ip)
        else
            -- Linux: Use timeout wrapper if available, otherwise just traceroute
            -- Check if timeout command exists
            local timeout_check = io.popen("which timeout 2>&1")
            local has_timeout = false
            if timeout_check then
                local timeout_output = timeout_check:read("*a")
                timeout_check:close()
                if timeout_output and timeout_output ~= "" and not string.find(timeout_output, "not found") and not string.find(timeout_output, "No such") then
                    has_timeout = true
                end
            end
            
            if has_timeout then
                -- Linux with timeout: timeout 30 traceroute -m 10 -w 1 <ip> (30 second overall timeout)
                cmd = string.format("timeout 30 traceroute -m 10 -w 1 %s 2>&1", ip)
            else
                -- Linux without timeout: traceroute -m 10 -w 1 <ip>
                cmd = string.format("traceroute -m 10 -w 1 %s 2>&1", ip)
            end
        end
    end
    
    log_message("Executing traceroute to: " .. ip .. " (max 10 hops, 1s timeout per hop)")
    
    local handle = io.popen(cmd)
    if not handle then
        return nil, "Failed to execute traceroute command."
    end
    
    local output = handle:read("*a")
    handle:close()
    
    if not output or output == "" then
        return nil, "No output from traceroute command."
    end
    
    -- Check if timeout occurred
    if string.find(output, "timeout") or string.find(output, "timed out") then
        output = output .. "\n\nNote: Traceroute was limited to 15 hops and may have timed out.\n" ..
                "This is normal for distant hosts or firewalled networks."
    end
    
    return output, nil
end

-- Format ping results
local function format_ping_result(output, ip)
    local result = "=== Ping Results ===\n\n"
    result = result .. "Target: " .. ip .. "\n"
    result = result .. "Command: " .. (package.config:sub(1,1) == "\\" and "ping -n 4" or "ping -c 4") .. "\n\n"
    result = result .. "--- Output ---\n"
    result = result .. output
    
    -- Extract statistics if available
    if package.config:sub(1,1) == "\\" then
        -- Windows ping output format: "Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)"
        local packets_sent = string.match(output, "Sent = (%d+)")
        local packets_received = string.match(output, "Received = (%d+)")
        local loss = string.match(output, "(%d+%%) loss")
        local min_time = string.match(output, "Minimum = (%d+)ms")
        local max_time = string.match(output, "Maximum = (%d+)ms")
        local avg_time = string.match(output, "Average = (%d+)ms")
        
        if packets_sent or packets_received then
            result = result .. "\n\n--- Statistics ---\n"
            if packets_sent then result = result .. "Packets Sent: " .. packets_sent .. "\n" end
            if packets_received then result = result .. "Packets Received: " .. packets_received .. "\n" end
            if loss then result = result .. "Packet Loss: " .. loss .. "\n" end
            if min_time then result = result .. "Minimum Time: " .. min_time .. " ms\n" end
            if max_time then result = result .. "Maximum Time: " .. max_time .. " ms\n" end
            if avg_time then result = result .. "Average Time: " .. avg_time .. " ms\n" end
        end
    else
        -- Unix ping output
        local packets_transmitted = string.match(output, "(%d+) packets transmitted")
        local packets_received = string.match(output, "(%d+) received")
        local loss = string.match(output, "(%d+%%) packet loss")
        local min_time = string.match(output, "min/avg/max/[%d%.]+ = ([%d%.]+)")
        local max_time = string.match(output, "min/avg/max/[%d%.]+ = [%d%.]+/([%d%.]+)/[%d%.]+")
        local avg_time = string.match(output, "min/avg/max/[%d%.]+ = [%d%.]+/([%d%.]+)/[%d%.]+")
        
        if packets_transmitted or packets_received then
            result = result .. "\n\n--- Statistics ---\n"
            if packets_transmitted then result = result .. "Packets Transmitted: " .. packets_transmitted .. "\n" end
            if packets_received then result = result .. "Packets Received: " .. packets_received .. "\n" end
            if loss then result = result .. "Packet Loss: " .. loss .. "\n" end
            if min_time then result = result .. "Minimum Time: " .. min_time .. " ms\n" end
            if max_time then result = result .. "Maximum Time: " .. max_time .. " ms\n" end
            if avg_time then result = result .. "Average Time: " .. avg_time .. " ms\n" end
        end
    end
    
    return result
end

-- Format traceroute results
local function format_traceroute_result(output, ip)
    local result = "=== Traceroute Results ===\n\n"
    result = result .. "Target: " .. ip .. "\n"
    result = result .. "Command: " .. (package.config:sub(1,1) == "\\" and "tracert -h 10 -w 1000" or "traceroute -m 10 -w 1") .. "\n"
    result = result .. "Max Hops: 10 (optimized for faster completion)\n"
    result = result .. "Timeout: 1 second per hop\n\n"
    result = result .. "--- Output ---\n"
    result = result .. output
    
    return result
end

-- Ping callback function
local function ping_callback(fieldname, ...)
    local fields = {...}
    local ip_raw = get_field_value(fieldname, "display", fields)
    
    if not ip_raw then
        show_error_window("Ping", "Could not extract IP address from packet")
        return
    end
    
    -- Extract IP address from the field value
    local ip = extract_ip_from_string(ip_raw)
    if not ip then
        show_error_window("Ping", "Could not extract valid IP address from: " .. ip_raw)
        return
    end
    
    -- Execute ping
    local output, err = ping_host(ip)
    if err then
        show_error_window("Ping Error", "Error executing ping:\n" .. err)
        return
    end
    
    local formatted = format_ping_result(output, ip)
    show_result_window("Ping: " .. ip, formatted)
end

-- Traceroute callback function
local function traceroute_callback(fieldname, ...)
    local fields = {...}
    local ip_raw = get_field_value(fieldname, "display", fields)
    
    if not ip_raw then
        show_error_window("Traceroute", "Could not extract IP address from packet")
        return
    end
    
    -- Extract IP address from the field value
    local ip = extract_ip_from_string(ip_raw)
    if not ip then
        show_error_window("Traceroute", "Could not extract valid IP address from: " .. ip_raw)
        return
    end
    
    -- Check if traceroute is available
    local traceroute_available, traceroute_path, cmd_name = check_traceroute_available()
    if not traceroute_available then
        local platform = "unknown"
        local install_instructions = ""
        
        if package.config:sub(1,1) == "\\" then
            platform = "Windows"
            install_instructions = "\n\nTracert is typically included with Windows.\n" ..
                                  "If tracert is not available, check your system PATH.\n" ..
                                  "Tracert should be located in C:\\Windows\\System32\\tracert.exe"
        else
            local uname_handle = io.popen("uname -s 2>&1")
            if uname_handle then
                local uname_output = uname_handle:read("*a")
                uname_handle:close()
                if string.find(uname_output, "Darwin") then
                    platform = "macOS"
                    install_instructions = "\n\nInstallation Instructions for macOS:\n" ..
                                          "brew install traceroute\n" ..
                                          "OR\n" ..
                                          "sudo port install traceroute"
                else
                    platform = "Linux"
                    install_instructions = "\n\nInstallation Instructions for Linux:\n" ..
                                          "Debian/Ubuntu: sudo apt-get install traceroute\n" ..
                                          "RedHat/CentOS: sudo yum install traceroute\n" ..
                                          "Fedora: sudo dnf install traceroute\n" ..
                                          "Arch: sudo pacman -S traceroute"
                end
            end
        end
        
        show_error_window("Traceroute Error", "Traceroute command is not installed or not found in PATH.\n\n" ..
                         "Platform detected: " .. platform .. "\n" ..
                         install_instructions)
        return
    end
    
    -- Create and show progress window immediately
    local progress_win = TextWindow.new("Traceroute: " .. ip)
    local progress_msg = "=== Traceroute in Progress ===\n\n" ..
                        "Tracing route to: " .. ip .. "\n" ..
                        "Max 10 hops, 1 second timeout per hop\n" ..
                        "This should complete in 10-20 seconds...\n\n" ..
                        "Please wait while traceroute completes..."
    progress_win:set(progress_msg)
    
    -- Force window to be displayed by logging and allowing UI to update
    -- This ensures the window appears before the blocking traceroute call
    log_message("Displaying traceroute progress window for: " .. ip)
    
    -- Small delay to ensure window is displayed (Wireshark needs time to render)
    -- Use os.execute with a short sleep to allow UI to update
    if package.config:sub(1,1) == "\\" then
        os.execute("timeout /t 0 /nobreak >nul 2>&1")
    else
        os.execute("sleep 0.1 2>&1")
    end
    
    -- Execute traceroute (this will block until complete)
    local output, err = traceroute_host(ip)
    if err then
        progress_win:close()
        show_error_window("Traceroute Error", "Error executing traceroute:\n" .. err)
        return
    end
    
    -- Update the window with results
    local formatted = format_traceroute_result(output, ip)
    progress_win:set(formatted)
end

-------------------------------------------------
-- Nmap Network Scanning Tools (⚠ Offensive)
-------------------------------------------------

-- Check if nmap command is available
local function check_nmap_available()
    -- First, try to find nmap using which/where
    local cmd_check
    if package.config:sub(1,1) == "\\" then
        -- Windows
        cmd_check = "where nmap 2>&1"
    else
        -- Unix-like (macOS, Linux)
        cmd_check = "which nmap 2>&1"
    end
    
    local handle = io.popen(cmd_check)
    if handle then
        local output = handle:read("*a")
        handle:close()
        
        -- Check if which/where found nmap
        if output and output ~= "" then
            -- Remove whitespace and check if it's a valid path
            local path = string.gsub(output, "%s+", "")
            -- Check for common "not found" messages
            if path ~= "" and 
               not string.find(output, "not found") and 
               not string.find(output, "No such") and
               not string.find(output, "not recognized") and
               not string.find(output, "cannot find") then
                -- Verify nmap actually works by checking version
                local test_handle = io.popen("nmap --version 2>&1")
                if test_handle then
                    local test_output = test_handle:read("*a")
                    test_handle:close()
                    -- If version command succeeds, nmap is available
                    if test_output and string.find(test_output, "Nmap") then
                        return true, path
                    end
                end
            end
        end
    end
    
    -- Fallback: Try to execute nmap directly (in case which/where fails but PATH is correct)
    local test_handle = io.popen("nmap --version 2>&1")
    if test_handle then
        local test_output = test_handle:read("*a")
        test_handle:close()
        if test_output and string.find(test_output, "Nmap") then
            -- Try to get the path
            local path_handle = io.popen(cmd_check)
            if path_handle then
                local path_output = path_handle:read("*a")
                path_handle:close()
                local path = string.gsub(path_output or "", "%s+", "")
                return true, (path ~= "" and path) or "nmap"
            end
            return true, "nmap"
        end
    end
    
    -- macOS-specific: Check common Homebrew paths (GUI apps don't inherit shell PATH)
    if package.config:sub(1,1) ~= "\\" then
        local uname_handle = io.popen("uname -s 2>&1")
        if uname_handle then
            local uname_output = uname_handle:read("*a")
            uname_handle:close()
            if string.find(uname_output, "Darwin") then
                -- macOS: Check common Homebrew locations
                local homebrew_paths = {
                    "/opt/homebrew/bin/nmap",      -- Apple Silicon (M1/M2/M3)
                    "/usr/local/bin/nmap",         -- Intel Mac or older Homebrew
                    os.getenv("HOME") .. "/.homebrew/bin/nmap",  -- Alternative location
                }
                
                for _, nmap_path in ipairs(homebrew_paths) do
                    -- Test if nmap exists at this path
                    local test_handle = io.popen(nmap_path .. " --version 2>&1")
                    if test_handle then
                        local test_output = test_handle:read("*a")
                        test_handle:close()
                        if test_output and string.find(test_output, "Nmap") then
                            log_message("Found nmap at: " .. nmap_path)
                            return true, nmap_path
                        end
                    end
                end
            end
        end
    end
    
    return false, nil
end

-- Check if running with root/sudo privileges
local function is_running_as_root()
    if package.config:sub(1,1) == "\\" then
        -- Windows: Check if running as Administrator
        -- On Windows, we can't easily check this from Lua, so assume false
        return false
    else
        -- Unix-like: Check if effective user ID is 0 (root)
        local id_handle = io.popen("id -u 2>&1")
        if id_handle then
            local id_output = id_handle:read("*a")
            id_handle:close()
            if id_output and string.match(id_output, "^0%s*$") then
                return true
            end
        end
        -- Also check EUID
        local euid_handle = io.popen("id -u 2>&1")
        if euid_handle then
            local euid_output = euid_handle:read("*a")
            euid_handle:close()
            if euid_output and string.match(euid_output, "^0%s*$") then
                return true
            end
        end
        return false
    end
end

-- Execute SYN scan (stealth scan)
local function nmap_syn_scan(ip)
    local nmap_available, nmap_path = check_nmap_available()
    if not nmap_available then
        local platform = "unknown"
        local install_instructions = ""
        
        if package.config:sub(1,1) == "\\" then
            platform = "Windows"
            install_instructions = "\n\nInstallation Instructions for Windows:\n" ..
                                  "1. Download Nmap from: https://nmap.org/download.html\n" ..
                                  "   OR install via Chocolatey: choco install nmap\n" ..
                                  "2. Add Nmap to your system PATH\n" ..
                                  "3. Restart Wireshark\n\n" ..
                                  "Note: SYN scan requires administrator privileges on Windows."
        else
            local uname_handle = io.popen("uname -s 2>&1")
            if uname_handle then
                local uname_output = uname_handle:read("*a")
                uname_handle:close()
                if string.find(uname_output, "Darwin") then
                    platform = "macOS"
                    install_instructions = "\n\nInstallation Instructions for macOS:\n" ..
                                          "brew install nmap\n" ..
                                          "OR\n" ..
                                          "sudo port install nmap\n\n" ..
                                          "Note: SYN scan requires root privileges (use sudo)."
                else
                    platform = "Linux"
                    install_instructions = "\n\nInstallation Instructions for Linux:\n" ..
                                          "Debian/Ubuntu: sudo apt-get install nmap\n" ..
                                          "RedHat/CentOS: sudo yum install nmap\n" ..
                                          "Fedora: sudo dnf install nmap\n" ..
                                          "Arch: sudo pacman -S nmap\n\n" ..
                                          "Note: SYN scan requires root privileges (use sudo)."
                end
            end
        end
        
        return nil, "Nmap is not installed or not found in PATH.\n\n" ..
                   "Platform detected: " .. platform .. "\n" ..
                   install_instructions
    end
    
    -- Check if running with root privileges
    local has_root = is_running_as_root()
    local use_stealth = has_root
    local scan_type = "TCP Connect"
    local scan_flag = "-sT"
    
    if has_root then
        -- Use SYN scan (stealth scan) if we have root
        scan_type = "SYN (Stealth)"
        scan_flag = "-sS"
        log_message("Wireshark running with root privileges, using SYN scan")
    else
        -- Use TCP connect scan if no root
        log_message("Wireshark not running with root privileges, using TCP connect scan")
    end
    
    -- Build scan command
    -- -Pn: Skip host discovery (assume host is up)
    -- -T4: Aggressive timing template
    -- Use full path if we have it, otherwise rely on PATH
    local nmap_cmd = (nmap_path and nmap_path ~= "nmap" and nmap_path) or "nmap"
    local cmd = string.format("%s %s -Pn -T4 %s 2>&1", nmap_cmd, scan_flag, ip)
    
    log_message("Executing nmap " .. scan_type .. " scan to: " .. ip)
    
    local handle = io.popen(cmd)
    if not handle then
        return nil, "Failed to execute nmap command."
    end
    
    local output = handle:read("*a")
    handle:close()
    
    if not output or output == "" then
        return nil, "No output from nmap command."
    end
    
    -- Check for permission errors (shouldn't happen with TCP connect, but check anyway)
    if string.find(output, "requires root privileges") or 
       string.find(output, "Operation not permitted") or
       string.find(output, "QUITTING") then
        -- If we tried SYN scan and it failed, fall back to TCP connect
        if use_stealth then
            log_message("SYN scan failed despite root, falling back to TCP connect scan")
            scan_type = "TCP Connect (Fallback)"
            scan_flag = "-sT"
            local fallback_cmd = string.format("%s -sT -Pn -T4 %s 2>&1", nmap_cmd, ip)
            
            local fallback_handle = io.popen(fallback_cmd)
            if fallback_handle then
                local fallback_output = fallback_handle:read("*a")
                fallback_handle:close()
                
                if fallback_output and fallback_output ~= "" then
                    output = fallback_output
                else
                    return nil, "Both SYN scan and TCP connect scan failed.\n\n" .. output
                end
            else
                return nil, "SYN scan failed and TCP connect scan could not be executed.\n\n" .. output
            end
        else
            return nil, "Scan failed with permission error.\n\n" .. output
        end
    end
    
    -- Add scan type info to output for formatting function
    output = "SCAN_TYPE:" .. scan_type .. "\n" .. output
    
    return output, nil
end

-- Execute service version scan
local function nmap_service_scan(ip)
    local nmap_available, nmap_path = check_nmap_available()
    if not nmap_available then
        local platform = "unknown"
        local install_instructions = ""
        
        if package.config:sub(1,1) == "\\" then
            platform = "Windows"
            install_instructions = "\n\nInstallation Instructions for Windows:\n" ..
                                  "1. Download Nmap from: https://nmap.org/download.html\n" ..
                                  "   OR install via Chocolatey: choco install nmap\n" ..
                                  "2. Add Nmap to your system PATH\n" ..
                                  "3. Restart Wireshark"
        else
            local uname_handle = io.popen("uname -s 2>&1")
            if uname_handle then
                local uname_output = uname_handle:read("*a")
                uname_handle:close()
                if string.find(uname_output, "Darwin") then
                    platform = "macOS"
                    install_instructions = "\n\nInstallation Instructions for macOS:\n" ..
                                          "brew install nmap\n" ..
                                          "OR\n" ..
                                          "sudo port install nmap"
                else
                    platform = "Linux"
                    install_instructions = "\n\nInstallation Instructions for Linux:\n" ..
                                          "Debian/Ubuntu: sudo apt-get install nmap\n" ..
                                          "RedHat/CentOS: sudo yum install nmap\n" ..
                                          "Fedora: sudo dnf install nmap\n" ..
                                          "Arch: sudo pacman -S nmap"
                end
            end
        end
        
        return nil, "Nmap is not installed or not found in PATH.\n\n" ..
                   "Platform detected: " .. platform .. "\n" ..
                   install_instructions
    end
    
    -- Build service scan command
    -- -sV: Version detection
    -- -p: Specific ports (21=FTP, 22=SSH, 23=Telnet, 80=HTTP, 443=HTTPS, 8080=HTTP-alt, 8443=HTTPS-alt, 3306=MySQL, 5432=PostgreSQL, 3389=RDP, 5900=VNC)
    -- Common service ports that often provide banners
    -- Use full path if we have it, otherwise rely on PATH
    local nmap_cmd = (nmap_path and nmap_path ~= "nmap" and nmap_path) or "nmap"
    local cmd = string.format("%s -sV -p 21,22,23,80,443,8080,8443,3306,5432,3389,5900,25,53,110,143,993,995 %s 2>&1", nmap_cmd, ip)
    
    log_message("Executing nmap service scan to: " .. ip)
    
    local handle = io.popen(cmd)
    if not handle then
        return nil, "Failed to execute nmap command."
    end
    
    local output = handle:read("*a")
    handle:close()
    
    if not output or output == "" then
        return nil, "No output from nmap command."
    end
    
    return output, nil
end

-- Execute Vulners vulnerability scan
local function nmap_vulners_scan(ip)
    local nmap_available, nmap_path = check_nmap_available()
    if not nmap_available then
        local platform = "unknown"
        local install_instructions = ""
        
        if package.config:sub(1,1) == "\\" then
            platform = "Windows"
            install_instructions = "\n\nInstallation Instructions for Windows:\n" ..
                                  "1. Download Nmap from: https://nmap.org/download.html\n" ..
                                  "   OR install via Chocolatey: choco install nmap\n" ..
                                  "2. Add Nmap to your system PATH\n" ..
                                  "3. Install Vulners script:\n" ..
                                  "   Download from: https://github.com/vulnersCom/nmap-vulners\n" ..
                                  "   Place vulners.nse in: C:\\Program Files (x86)\\Nmap\\scripts\\\n" ..
                                  "4. Restart Wireshark"
        else
            local uname_handle = io.popen("uname -s 2>&1")
            if uname_handle then
                local uname_output = uname_handle:read("*a")
                uname_handle:close()
                if string.find(uname_output, "Darwin") then
                    platform = "macOS"
                    install_instructions = "\n\nInstallation Instructions for macOS:\n" ..
                                          "brew install nmap\n" ..
                                          "OR\n" ..
                                          "sudo port install nmap\n\n" ..
                                          "Install Vulners script:\n" ..
                                          "wget -O /opt/homebrew/share/nmap/scripts/vulners.nse https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse\n" ..
                                          "OR\n" ..
                                          "sudo wget -O /usr/local/share/nmap/scripts/vulners.nse https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse"
                else
                    platform = "Linux"
                    install_instructions = "\n\nInstallation Instructions for Linux:\n" ..
                                          "Debian/Ubuntu: sudo apt-get install nmap\n" ..
                                          "RedHat/CentOS: sudo yum install nmap\n" ..
                                          "Fedora: sudo dnf install nmap\n" ..
                                          "Arch: sudo pacman -S nmap\n\n" ..
                                          "Install Vulners script:\n" ..
                                          "sudo wget -O /usr/share/nmap/scripts/vulners.nse https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse\n" ..
                                          "sudo nmap --script-updatedb"
                end
            end
        end
        
        return nil, "Nmap is not installed or not found in PATH.\n\n" ..
                   "Platform detected: " .. platform .. "\n" ..
                   install_instructions
    end
    
    -- Build Vulners scan command
    -- --script vulners: Run vulners script
    -- -sV: Version detection (required for vulners)
    -- -Pn: Skip host discovery
    -- Use full path if we have it, otherwise rely on PATH
    local nmap_cmd = (nmap_path and nmap_path ~= "nmap" and nmap_path) or "nmap"
    local cmd = string.format("%s --script vulners -sV -Pn %s 2>&1", nmap_cmd, ip)
    
    log_message("Executing nmap Vulners vulnerability scan to: " .. ip)
    
    local handle = io.popen(cmd)
    if not handle then
        return nil, "Failed to execute nmap command."
    end
    
    local output = handle:read("*a")
    handle:close()
    
    if not output or output == "" then
        return nil, "No output from nmap command."
    end
    
    -- Check for script not found errors
    if string.find(output, "vulners") and 
       (string.find(output, "not found") or string.find(output, "SCRIPT ERROR") or string.find(output, "does not exist")) then
        return nil, "Vulners script not found.\n\n" ..
                   "Please install the Vulners NSE script:\n" ..
                   "https://github.com/vulnersCom/nmap-vulners\n\n" ..
                   "Raw error:\n" .. string.sub(output, 1, 500)
    end
    
    -- Check for other errors
    if string.find(output, "QUITTING") or string.find(output, "FATAL") then
        return nil, "Vulners scan failed.\n\n" ..
                   "Raw error:\n" .. string.sub(output, 1, 500)
    end
    
    return output, nil
end

-- Format SYN scan results
local function format_syn_scan_result(output, ip)
    local result = "=== Nmap Port Scan Results (⚠ Offensive Tool) ===\n\n"
    result = result .. "⚠ WARNING: This is a network reconnaissance tool.\n"
    result = result .. "Only use on systems you own or have explicit permission to scan.\n\n"
    result = result .. "Target: " .. ip .. "\n"
    
    -- Extract scan type from output (added by nmap_syn_scan function)
    local scan_type = "SYN (Stealth)"
    local scan_cmd = "nmap -sS -Pn -T4"
    local scan_note = ""
    
    if string.find(output, "SCAN_TYPE:") then
        scan_type = string.match(output, "SCAN_TYPE:([^\n]+)")
        output = string.gsub(output, "SCAN_TYPE:[^\n]+\n", "") -- Remove the marker
    end
    
    if string.find(scan_type, "TCP Connect") then
        scan_cmd = "nmap -sT -Pn -T4"
        scan_note = "\nNote: TCP Connect Scan was used (no root privileges required).\n" ..
                   "This scan type is slower and more detectable than SYN scan.\n" ..
                   "To use SYN scan, run Wireshark with: sudo wireshark\n\n"
    else
        scan_note = "\nNote: SYN (Stealth) Scan was used (Wireshark running with root privileges).\n\n"
    end
    
    result = result .. "Command: " .. scan_cmd .. "\n"
    result = result .. "Scan Type: " .. scan_type .. scan_note
    result = result .. "--- Output ---\n"
    result = result .. output
    
    return result
end

-- Format service scan results
local function format_service_scan_result(output, ip)
    local result = "=== Nmap Service Scan Results (⚠ Offensive Tool) ===\n\n"
    result = result .. "⚠ WARNING: This is a network reconnaissance tool.\n"
    result = result .. "Only use on systems you own or have explicit permission to scan.\n\n"
    result = result .. "Target: " .. ip .. "\n"
    result = result .. "Command: nmap -sV -p 21,22,23,80,443,8080,8443,3306,5432,3389,5900,25,53,110,143,993,995\n"
    result = result .. "Scan Type: Service Version Detection\n"
    result = result .. "Ports Scanned: 21 (FTP), 22 (SSH), 23 (Telnet), 80 (HTTP), 443 (HTTPS),\n"
    result = result .. "               8080 (HTTP-alt), 8443 (HTTPS-alt), 3306 (MySQL),\n"
    result = result .. "               5432 (PostgreSQL), 3389 (RDP), 5900 (VNC),\n"
    result = result .. "               25 (SMTP), 53 (DNS), 110 (POP3), 143 (IMAP),\n"
    result = result .. "               993 (IMAPS), 995 (POP3S)\n\n"
    result = result .. "--- Output ---\n"
    result = result .. output
    
    return result
end

-- Format Vulners scan results
local function format_vulners_scan_result(output, ip)
    local result = "=== Nmap Vulners Vulnerability Scan Results (⚠ Offensive Tool) ===\n\n"
    result = result .. "⚠ WARNING: This is a network vulnerability scanning tool.\n"
    result = result .. "Only use on systems you own or have explicit permission to scan.\n\n"
    result = result .. "Target: " .. ip .. "\n"
    result = result .. "Command: nmap --script vulners -sV -Pn\n"
    result = result .. "Scan Type: Vulnerability Detection (Vulners.com database)\n\n"
    result = result .. "--- Output ---\n"
    result = result .. output
    result = result .. "\n\n--- Additional Information ---\n"
    result = result .. "Vulners uses the Vulners.com vulnerability database to identify\n"
    result = result .. "known security vulnerabilities in detected services.\n"
    result = result .. "For more details, visit: https://vulners.com\n"
    
    return result
end

-- SYN scan callback function
local function nmap_syn_scan_callback(fieldname, ...)
    local fields = {...}
    local ip_raw = get_field_value(fieldname, "display", fields)
    
    if not ip_raw then
        show_error_window("Nmap SYN Scan", "Could not extract IP address from packet")
        return
    end
    
    -- Extract IP address from the field value
    local ip = extract_ip_from_string(ip_raw)
    if not ip then
        show_error_window("Nmap SYN Scan", "Could not extract valid IP address from: " .. ip_raw)
        return
    end
    
    -- Execute SYN scan
    local output, err = nmap_syn_scan(ip)
    if err then
        show_error_window("Nmap SYN Scan Error", "Error executing nmap SYN scan:\n" .. err)
        return
    end
    
    local formatted = format_syn_scan_result(output, ip)
    show_result_window("Nmap SYN Scan: " .. ip, formatted)
end

-- Service scan callback function
local function nmap_service_scan_callback(fieldname, ...)
    local fields = {...}
    local ip_raw = get_field_value(fieldname, "display", fields)
    
    if not ip_raw then
        show_error_window("Nmap Service Scan", "Could not extract IP address from packet")
        return
    end
    
    -- Extract IP address from the field value
    local ip = extract_ip_from_string(ip_raw)
    if not ip then
        show_error_window("Nmap Service Scan", "Could not extract valid IP address from: " .. ip_raw)
        return
    end
    
    -- Execute service scan
    local output, err = nmap_service_scan(ip)
    if err then
        show_error_window("Nmap Service Scan Error", "Error executing nmap service scan:\n" .. err)
        return
    end
    
    local formatted = format_service_scan_result(output, ip)
    show_result_window("Nmap Service Scan: " .. ip, formatted)
end

-- Vulners scan callback function
local function nmap_vulners_scan_callback(fieldname, ...)
    local fields = {...}
    local ip_raw = get_field_value(fieldname, "display", fields)
    
    if not ip_raw then
        show_error_window("Nmap Vulners Scan", "Could not extract IP address from packet")
        return
    end
    
    -- Extract IP address from the field value
    local ip = extract_ip_from_string(ip_raw)
    if not ip then
        show_error_window("Nmap Vulners Scan", "Could not extract valid IP address from: " .. ip_raw)
        return
    end
    
    -- Check if this is an RFC 1918 private address
    if is_rfc1918_private(ip) then
        local formatted = format_rfc1918_info(ip)
        show_result_window("Private IP Address: " .. ip, formatted)
        return
    end
    
    -- Execute Vulners scan
    local output, err = nmap_vulners_scan(ip)
    if err then
        show_error_window("Nmap Vulners Scan Error", "Error executing nmap Vulners scan:\n" .. err)
        return
    end
    
    local formatted = format_vulners_scan_result(output, ip)
    show_result_window("Nmap Vulners Vulnerability Scan: " .. ip, formatted)
end

local function email_analysis_callback(...)
    local fields = {...}
    local email = get_field_value("imf.from", "value", fields)
    
    if not email then
        email = get_field_value("smtp.req.parameter", "value", fields)
    end
    
    if not email then
        show_error_window("Email Analysis", "Could not extract email address from packet")
        return
    end
    
    local result, err = lookup_email_reputation(email)
    if err then
        show_error_window("Email Analysis Error", "Error analyzing email:\n" .. err)
        return
    end
    
    show_result_window("Email Analysis: " .. extract_email(email), result)
end

-------------------------------------------------
-- Register Packet Menus
-------------------------------------------------

-- Check if register_packet_menu is available (Wireshark 4.2+)
if not register_packet_menu then
    log_message("ERROR: register_packet_menu not available. Wireshark 4.2+ required.")
    log_message("Plugin requires Wireshark 4.2 or later for packet menu support.")
else
    log_message("register_packet_menu available, registering menus...")
    
    -- Wrap menu registration in error handling to prevent silent failures
    local function safe_register_menu(path, callback, field)
        local success, err = pcall(function()
            register_packet_menu(path, callback, field)
        end)
        if not success then
            log_message("ERROR: Failed to register menu: " .. path .. " - " .. tostring(err))
        else
            log_message("Registered menu: " .. path)
        end
    end

-- DNS Registration Info
if CONFIG.RDAP_ENABLED then
    safe_register_menu("DNS/ASK/DNS Registration Info (RDAP)", dns_rdap_callback, "dns.qry.name")
end

-- DNS Domain Reputation (VirusTotal)
if CONFIG.VIRUSTOTAL_ENABLED then
    safe_register_menu("DNS/ASK/Domain Reputation (VirusTotal)", virustotal_domain_callback, "dns.qry.name")
end

-- TLS Certificate Analysis
safe_register_menu("TLS/ASK/Certificate Analysis", tls_certificate_callback, "tls.handshake.certificate")
safe_register_menu("TLS/ASK/Certificate Analysis", tls_certificate_callback, "tls.handshake.certificate.subject")
safe_register_menu("TLS/ASK/Certificate Analysis", tls_certificate_callback, "tls.handshake.certificate.issuer")

-- Three Certificate Checking Options:
-- 1. Quick Certificate Check (OpenSSL) - Fast and simple, no API
-- 2. Certificate Validator (SSLChecker.com) - Quick API check with basic info
-- 3. SSL Security Analysis (SSLLabs) - Comprehensive security grading (slow)

-- Quick Certificate Check (OpenSSL - Instant, requires OpenSSL)
safe_register_menu("TLS/ASK/Quick Certificate Check", quick_cert_check_callback, "tls.handshake.extensions_server_name")

-- Certificate Validator (SSLChecker.com - Fast API, requires curl)
safe_register_menu("TLS/ASK/Certificate Validator", cert_validator_callback, "tls.handshake.extensions_server_name")

-- SSL Security Analysis (SSLLabs - Comprehensive, requires curl, slow)
safe_register_menu("TLS/ASK/SSL Security Analysis (may take 1-2 min)", ssl_security_analysis_callback, "tls.handshake.extensions_server_name")


-- Certificate Transparency
if CONFIG.CERT_TRANSPARENCY_ENABLED then
    safe_register_menu("DNS/ASK/Certificate Transparency", cert_transparency_callback, "dns.qry.name")
    safe_register_menu("TLS/ASK/Certificate Transparency", cert_transparency_callback, "tls.handshake.extensions_server_name")
end

-- IP Registration via RDAP Bootstrap (IPv4 & IPv6) - automatically routes to correct RIR
if CONFIG.ARIN_RDAP_ENABLED then
    safe_register_menu("IP Src/ASK/IP Registration Info (RDAP)", function(...) ip_rdap_callback("ip.src", ...) end, "ip.src")
    safe_register_menu("IP Dest/ASK/IP Registration Info (RDAP)", function(...) ip_rdap_callback("ip.dst", ...) end, "ip.dst")
    safe_register_menu("IPv6 Src/ASK/IP Registration Info (RDAP)", function(...) ip_rdap_callback("ipv6.src", ...) end, "ipv6.src")
    safe_register_menu("IPv6 Dest/ASK/IP Registration Info (RDAP)", function(...) ip_rdap_callback("ipv6.dst", ...) end, "ipv6.dst")
end

-- IP Reputation (AbuseIPDB)
if CONFIG.ABUSEIPDB_ENABLED then
    safe_register_menu("IP Src/ASK/IP Reputation (AbuseIPDB)", function(...) ip_reputation_callback("ip.src", ...) end, "ip.src")
    safe_register_menu("IP Dest/ASK/IP Reputation (AbuseIPDB)", function(...) ip_reputation_callback("ip.dst", ...) end, "ip.dst")
end

-- IP Reputation (VirusTotal)
if CONFIG.VIRUSTOTAL_ENABLED then
    safe_register_menu("IP Src/ASK/IP Reputation (VirusTotal)", function(...) virustotal_ip_callback("ip.src", ...) end, "ip.src")
    safe_register_menu("IP Dest/ASK/IP Reputation (VirusTotal)", function(...) virustotal_ip_callback("ip.dst", ...) end, "ip.dst")
end

-- IP Intelligence (Shodan)
if CONFIG.SHODAN_ENABLED then
    safe_register_menu("IP Src/ASK/IP Intelligence (Shodan)", function(...) shodan_ip_callback("ip.src", ...) end, "ip.src")
    safe_register_menu("IP Dest/ASK/IP Intelligence (Shodan)", function(...) shodan_ip_callback("ip.dst", ...) end, "ip.dst")
end

-- IP Intelligence (IPinfo)
if CONFIG.IPINFO_ENABLED then
    safe_register_menu("IP Src/ASK/IP Intelligence (IPinfo)", function(...) ipinfo_ip_callback("ip.src", ...) end, "ip.src")
    safe_register_menu("IP Dest/ASK/IP Intelligence (IPinfo)", function(...) ipinfo_ip_callback("ip.dst", ...) end, "ip.dst")
    safe_register_menu("IPv6 Src/ASK/IP Intelligence (IPinfo)", function(...) ipinfo_ip_callback("ipv6.src", ...) end, "ipv6.src")
    safe_register_menu("IPv6 Dest/ASK/IP Intelligence (IPinfo)", function(...) ipinfo_ip_callback("ipv6.dst", ...) end, "ipv6.dst")
end

-- IP Intelligence (GreyNoise)
if CONFIG.GREYNOISE_ENABLED then
    safe_register_menu("IP Src/ASK/IP Intelligence (GreyNoise)", function(...) greynoise_ip_callback("ip.src", ...) end, "ip.src")
    safe_register_menu("IP Dest/ASK/IP Intelligence (GreyNoise)", function(...) greynoise_ip_callback("ip.dst", ...) end, "ip.dst")
    safe_register_menu("IPv6 Src/ASK/IP Intelligence (GreyNoise)", function(...) greynoise_ip_callback("ipv6.src", ...) end, "ipv6.src")
    safe_register_menu("IPv6 Dest/ASK/IP Intelligence (GreyNoise)", function(...) greynoise_ip_callback("ipv6.dst", ...) end, "ipv6.dst")
end

-- IP Intelligence (AlienVault OTX)
if CONFIG.OTX_ENABLED then
    safe_register_menu("IP Src/ASK/IP Intelligence (OTX)", function(...) otx_ip_callback("ip.src", ...) end, "ip.src")
    safe_register_menu("IP Dest/ASK/IP Intelligence (OTX)", function(...) otx_ip_callback("ip.dst", ...) end, "ip.dst")
    safe_register_menu("IPv6 Src/ASK/IP Intelligence (OTX)", function(...) otx_ip_callback("ipv6.src", ...) end, "ipv6.src")
    safe_register_menu("IPv6 Dest/ASK/IP Intelligence (OTX)", function(...) otx_ip_callback("ipv6.dst", ...) end, "ipv6.dst")
end

-- Host Intelligence (URLhaus)
if CONFIG.ABUSECH_ENABLED then
    safe_register_menu("IP Src/ASK/Host Intelligence (URLhaus)", function(...) urlhaus_host_callback("ip.src", ...) end, "ip.src")
    safe_register_menu("IP Dest/ASK/Host Intelligence (URLhaus)", function(...) urlhaus_host_callback("ip.dst", ...) end, "ip.dst")
    safe_register_menu("IPv6 Src/ASK/Host Intelligence (URLhaus)", function(...) urlhaus_host_callback("ipv6.src", ...) end, "ipv6.src")
    safe_register_menu("IPv6 Dest/ASK/Host Intelligence (URLhaus)", function(...) urlhaus_host_callback("ipv6.dst", ...) end, "ipv6.dst")
end

-- IOC Intelligence (ThreatFox)
if CONFIG.ABUSECH_ENABLED then
    safe_register_menu("IP Src/ASK/IOC Intelligence (ThreatFox)", function(...) threatfox_ioc_callback("ip.src", ...) end, "ip.src")
    safe_register_menu("IP Dest/ASK/IOC Intelligence (ThreatFox)", function(...) threatfox_ioc_callback("ip.dst", ...) end, "ip.dst")
    safe_register_menu("IPv6 Src/ASK/IOC Intelligence (ThreatFox)", function(...) threatfox_ioc_callback("ipv6.src", ...) end, "ipv6.src")
    safe_register_menu("IPv6 Dest/ASK/IOC Intelligence (ThreatFox)", function(...) threatfox_ioc_callback("ipv6.dst", ...) end, "ipv6.dst")
    safe_register_menu("DNS/ASK/IOC Intelligence (ThreatFox)", function(...) threatfox_ioc_callback("dns.qry.name", ...) end, "dns.qry.name")
    safe_register_menu("HTTP/ASK/IOC Intelligence (ThreatFox)", function(...) threatfox_ioc_callback("http.request.full_uri", ...) end, "http.request.full_uri")
end

-- DNS Analytics for IP addresses (Reverse DNS + Forward DNS + Registration)
safe_register_menu("IP Src/ASK/DNS Analytics", function(...) dns_analytics_callback("ip.src", ...) end, "ip.src")
safe_register_menu("IP Dest/ASK/DNS Analytics", function(...) dns_analytics_callback("ip.dst", ...) end, "ip.dst")
safe_register_menu("IPv6 Src/ASK/DNS Analytics", function(...) dns_analytics_callback("ipv6.src", ...) end, "ipv6.src")
safe_register_menu("IPv6 Dest/ASK/DNS Analytics", function(...) dns_analytics_callback("ipv6.dst", ...) end, "ipv6.dst")

-- Network Diagnostic Tools (Ping & Traceroute)
safe_register_menu("IP Src/ASK/Ping Host", function(...) ping_callback("ip.src", ...) end, "ip.src")
safe_register_menu("IP Src/ASK/Traceroute to Host", function(...) traceroute_callback("ip.src", ...) end, "ip.src")
safe_register_menu("IP Dest/ASK/Ping Host", function(...) ping_callback("ip.dst", ...) end, "ip.dst")
safe_register_menu("IP Dest/ASK/Traceroute to Host", function(...) traceroute_callback("ip.dst", ...) end, "ip.dst")
safe_register_menu("IPv6 Src/ASK/Ping Host", function(...) ping_callback("ipv6.src", ...) end, "ipv6.src")
safe_register_menu("IPv6 Src/ASK/Traceroute to Host", function(...) traceroute_callback("ipv6.src", ...) end, "ipv6.src")
safe_register_menu("IPv6 Dest/ASK/Ping Host", function(...) ping_callback("ipv6.dst", ...) end, "ipv6.dst")
safe_register_menu("IPv6 Dest/ASK/Traceroute to Host", function(...) traceroute_callback("ipv6.dst", ...) end, "ipv6.dst")

-- Nmap Network Scanning Tools (⚠ Offensive - Use Only with Permission)
safe_register_menu("IP Src/ASK/⚠ SYN Scan (Offensive)", function(...) nmap_syn_scan_callback("ip.src", ...) end, "ip.src")
safe_register_menu("IP Src/ASK/⚠ Service Scan (Offensive)", function(...) nmap_service_scan_callback("ip.src", ...) end, "ip.src")
safe_register_menu("IP Src/ASK/⚠ Vulners Scan (Offensive)", function(...) nmap_vulners_scan_callback("ip.src", ...) end, "ip.src")
safe_register_menu("IP Dest/ASK/⚠ SYN Scan (Offensive)", function(...) nmap_syn_scan_callback("ip.dst", ...) end, "ip.dst")
safe_register_menu("IP Dest/ASK/⚠ Service Scan (Offensive)", function(...) nmap_service_scan_callback("ip.dst", ...) end, "ip.dst")
safe_register_menu("IP Dest/ASK/⚠ Vulners Scan (Offensive)", function(...) nmap_vulners_scan_callback("ip.dst", ...) end, "ip.dst")
safe_register_menu("IPv6 Src/ASK/⚠ SYN Scan (Offensive)", function(...) nmap_syn_scan_callback("ipv6.src", ...) end, "ipv6.src")
safe_register_menu("IPv6 Src/ASK/⚠ Service Scan (Offensive)", function(...) nmap_service_scan_callback("ipv6.src", ...) end, "ipv6.src")
safe_register_menu("IPv6 Src/ASK/⚠ Vulners Scan (Offensive)", function(...) nmap_vulners_scan_callback("ipv6.src", ...) end, "ipv6.src")
safe_register_menu("IPv6 Dest/ASK/⚠ SYN Scan (Offensive)", function(...) nmap_syn_scan_callback("ipv6.dst", ...) end, "ipv6.dst")
safe_register_menu("IPv6 Dest/ASK/⚠ Service Scan (Offensive)", function(...) nmap_service_scan_callback("ipv6.dst", ...) end, "ipv6.dst")
safe_register_menu("IPv6 Dest/ASK/⚠ Vulners Scan (Offensive)", function(...) nmap_vulners_scan_callback("ipv6.dst", ...) end, "ipv6.dst")

-- URL Categorization (urlscan.io)
if CONFIG.URLSCAN_ENABLED then
    safe_register_menu("HTTP/ASK/URL Reputation (urlscan.io)", url_reputation_callback, "http.request.full_uri")
end

-- URL Reputation (VirusTotal)
if CONFIG.VIRUSTOTAL_ENABLED then
    safe_register_menu("HTTP/ASK/URL Reputation (VirusTotal)", virustotal_url_callback, "http.request.full_uri")
end

-- URL Intelligence (AlienVault OTX)
if CONFIG.OTX_ENABLED then
    safe_register_menu("HTTP/ASK/URL Intelligence (OTX)", otx_url_callback, "http.request.full_uri")
end

-- URL Intelligence (URLhaus)
if CONFIG.ABUSECH_ENABLED then
    safe_register_menu("HTTP/ASK/URL Intelligence (URLhaus)", urlhaus_url_callback, "http.request.full_uri")
end

-- Email Analysis
safe_register_menu("IMF/ASK/Email Analysis", email_analysis_callback, "imf.from")
safe_register_menu("SMTP/ASK/Email Analysis", email_analysis_callback, "smtp.req.parameter")
    
    -- Log successful loading and menu registrations
    log_message("Analyst's Shark Knife (ASK) plugin v0.2.5 loaded successfully")
    log_message("Features enabled: RDAP, ARIN RDAP, AbuseIPDB, urlscan.io, VirusTotal, Shodan, IPinfo, GreyNoise, AlienVault OTX, Abuse.ch (URLhaus/ThreatFox), TLS Certificate Analysis, Certificate Validity Check, Certificate Transparency, Email Analysis, DNS Analytics, Ping, Traceroute, Nmap Scans (SYN, Service, Vulners)")
    
    -- Debug: Log menu registration counts
    local menu_count = 0
    if CONFIG.RDAP_ENABLED then menu_count = menu_count + 1 end
    if CONFIG.ARIN_RDAP_ENABLED then menu_count = menu_count + 4 end
    menu_count = menu_count + 4 -- DNS Analytics (4 menu items: IPv4/IPv6 Src/Dest)
    menu_count = menu_count + 4 -- Ping & Traceroute (4 menu items: IPv4/IPv6 Dest)
    menu_count = menu_count + 6 -- Nmap Scans (6 menu items: 3 scan types × IPv4/IPv6 Dest)
    if CONFIG.ABUSEIPDB_ENABLED then menu_count = menu_count + 2 end
    if CONFIG.VIRUSTOTAL_ENABLED then menu_count = menu_count + 3 end
    if CONFIG.SHODAN_ENABLED then menu_count = menu_count + 2 end
    if CONFIG.IPINFO_ENABLED then menu_count = menu_count + 4 end
    if CONFIG.GREYNOISE_ENABLED then menu_count = menu_count + 4 end
    if CONFIG.OTX_ENABLED then menu_count = menu_count + 6 end  -- OTX: 4 IP (IPv4/IPv6 Src/Dest) + 1 Domain + 1 URL
    if CONFIG.ABUSECH_ENABLED then menu_count = menu_count + 11 end  -- Abuse.ch: 1 URL (URLhaus) + 4 Host (URLhaus) + 6 IOC (ThreatFox: 4 IP + 1 DNS + 1 HTTP)
    if CONFIG.URLSCAN_ENABLED then menu_count = menu_count + 1 end
    menu_count = menu_count + 3 -- TLS Certificate Analysis (3 menu items)
    menu_count = menu_count + 2 -- Certificate Validity Check (2 menu items: TLS SNI + HTTP Host)
    if CONFIG.CERT_TRANSPARENCY_ENABLED then menu_count = menu_count + 2 end
    menu_count = menu_count + 2 -- Email analysis
    
    log_message("Registered " .. menu_count .. " packet menu items")
end
