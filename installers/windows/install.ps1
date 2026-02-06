# ASK (Analyst's Shark Knife) Installation Script for Windows
# Version: 0.2.7

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "ASK (Analyst's Shark Knife) Installer" -ForegroundColor Cyan
Write-Host "Version 0.2.7 - Windows" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Wireshark is installed (try multiple methods)
$wiresharkExe = $null
$wiresharkFound = $false

# Method 1: Check PATH
$wiresharkPath = Get-Command wireshark -ErrorAction SilentlyContinue
if ($wiresharkPath) {
    $wiresharkExe = $wiresharkPath.Source
    $wiresharkFound = $true
}

# Method 2: Check common installation locations
if (-not $wiresharkFound) {
    $commonPaths = @(
        "${env:ProgramFiles}\Wireshark\wireshark.exe",
        "${env:ProgramFiles(x86)}\Wireshark\wireshark.exe",
        "${env:LOCALAPPDATA}\Programs\Wireshark\wireshark.exe"
    )
    
    foreach ($path in $commonPaths) {
        if (Test-Path $path) {
            $wiresharkExe = $path
            $wiresharkFound = $true
            Write-Host "[+] Found Wireshark at: $path" -ForegroundColor Green
            break
        }
    }
}

# Method 3: Check registry for installed programs
if (-not $wiresharkFound) {
    try {
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        foreach ($regPath in $regPaths) {
            $installed = Get-ItemProperty $regPath -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*Wireshark*" }
            if ($installed -and $installed.InstallLocation) {
                $exePath = Join-Path $installed.InstallLocation "wireshark.exe"
                if (Test-Path $exePath) {
                    $wiresharkExe = $exePath
                    $wiresharkFound = $true
                    Write-Host "[+] Found Wireshark via registry: $exePath" -ForegroundColor Green
                    break
                }
            }
        }
    } catch {
        # Registry check failed, continue anyway
    }
}

# Get Wireshark version (optional - proceed even if we can't find exe)
$WIRESHARK_VERSION = $null
if ($wiresharkExe) {
    try {
        $versionOutput = & $wiresharkExe -v 2>&1 | Select-Object -First 1
        $versionMatch = $versionOutput -match '(\d+\.\d+)'
        if ($versionMatch) {
            $WIRESHARK_VERSION = $matches[1]
            Write-Host "[+] Found Wireshark version: $WIRESHARK_VERSION" -ForegroundColor Green
        }
    } catch {
        # Version check failed, but continue anyway
    }
}

# Note: We proceed with installation even if Wireshark.exe isn't found
# because the plugins directory is standard and Wireshark will load plugins
# from there when it runs, regardless of where wireshark.exe is located
Write-Host ""
if (-not $wiresharkFound) {
    Write-Host "[!] Could not locate wireshark.exe, but proceeding with installation." -ForegroundColor Yellow
    Write-Host "    Plugins will be installed to the standard location: $env:APPDATA\Wireshark\plugins" -ForegroundColor Yellow
    Write-Host "    If Wireshark is installed, it will load the plugins automatically when you restart it." -ForegroundColor Yellow
    Write-Host ""
} else {
    Write-Host "[+] Wireshark detection successful" -ForegroundColor Green
    Write-Host ""
}

# Create plugins directory
$PLUGINS_DIR = "$env:APPDATA\Wireshark\plugins"
if (-not (Test-Path $PLUGINS_DIR)) {
    New-Item -ItemType Directory -Path $PLUGINS_DIR -Force | Out-Null
}
Write-Host "[+] Created plugins directory: $PLUGINS_DIR" -ForegroundColor Green

# Get script and project directories
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$PROJECT_ROOT = Split-Path -Parent (Split-Path -Parent $SCRIPT_DIR)
$pluginSource = Join-Path $SCRIPT_DIR "ask.lua"
$pluginDest = Join-Path $PLUGINS_DIR "ask.lua"

# Function to extract version from Lua file
function Extract-Version {
    param([string]$FilePath)
    if (Test-Path $FilePath) {
        $content = Get-Content $FilePath -Raw
        if ($content -match 'version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"') {
            return $matches[1]
        }
    }
    return $null
}

# Check for existing installation and offer upgrade
$skipAskInstall = $false
if (Test-Path $pluginDest) {
    $installedVersion = Extract-Version -FilePath $pluginDest
    $sourceVersion = Extract-Version -FilePath $pluginSource
    
    if ($installedVersion -and $sourceVersion) {
        try {
            $installedVer = [Version]$installedVersion
            $sourceVer = [Version]$sourceVersion
            
            if ($sourceVer -gt $installedVer) {
                Write-Host ""
                Write-Host "[*] Existing installation detected:" -ForegroundColor Cyan
                Write-Host "   Installed version: $installedVersion" -ForegroundColor Yellow
                Write-Host "   Available version: $sourceVersion" -ForegroundColor Green
                $upgrade = Read-Host "Upgrade to version $sourceVersion? (y/n)"
                if ($upgrade -ne "y" -and $upgrade -ne "Y") {
                    Write-Host "Skipping upgrade. Installation cancelled." -ForegroundColor Yellow
                    exit 0
                }
            } elseif ($sourceVer -eq $installedVer) {
                Write-Host "[+] Already installed version $installedVersion" -ForegroundColor Green
                $reinstall = Read-Host "Reinstall anyway? (y/n)"
                if ($reinstall -ne "y" -and $reinstall -ne "Y") {
                    Write-Host "Skipping reinstallation." -ForegroundColor Yellow
                    $skipAskInstall = $true
                }
            }
        } catch {
            # Version parsing failed, fall through to timestamp check
        }
    }
    
    # Fallback to timestamp comparison
    if (-not $skipAskInstall) {
        if (Test-Path $pluginDest) {
            $installedTime = (Get-Item $pluginDest).LastWriteTime
            $sourceTime = (Get-Item $pluginSource).LastWriteTime
            if ($sourceTime -gt $installedTime) {
                Write-Host ""
                Write-Host "[*] Existing installation detected (newer source file found)" -ForegroundColor Cyan
                $upgrade = Read-Host "Upgrade installation? (y/n)"
                if ($upgrade -ne "y" -and $upgrade -ne "Y") {
                    Write-Host "Skipping upgrade. Installation cancelled." -ForegroundColor Yellow
                    exit 0
                }
            }
        }
    }
}

# Install ask.lua
if (-not $skipAskInstall) {
    if (Test-Path $pluginSource) {
        Copy-Item $pluginSource $pluginDest -Force
        $sourceVersion = Extract-Version -FilePath $pluginSource
        if ($sourceVersion) {
            Write-Host "[+] Installed ask.lua version $sourceVersion" -ForegroundColor Green
        } else {
            Write-Host "[+] Installed ask.lua" -ForegroundColor Green
        }
    } else {
        Write-Host "[!] ask.lua not found in installer directory" -ForegroundColor Yellow
        exit 1
    }
}

# Offer to install Scan Detector
Write-Host ""
$scanDetectorSource = Join-Path $PROJECT_ROOT "Scan_Detector\scan_detector.lua"
$scanDetectorDest = Join-Path $PLUGINS_DIR "scan_detector.lua"

if (Test-Path $scanDetectorSource) {
    if (Test-Path $scanDetectorDest) {
        $installedSdVersion = Extract-Version -FilePath $scanDetectorDest
        $sourceSdVersion = Extract-Version -FilePath $scanDetectorSource
        
        if ($installedSdVersion -and $sourceSdVersion) {
            $versionHandled = $false
            try {
                $installedSdVer = [Version]$installedSdVersion
                $sourceSdVer = [Version]$sourceSdVersion
                
                if ($sourceSdVer -gt $installedSdVer) {
                    Write-Host "[*] Scan Detector already installed:" -ForegroundColor Cyan
                    Write-Host "   Installed version: $installedSdVersion" -ForegroundColor Yellow
                    Write-Host "   Available version: $sourceSdVersion" -ForegroundColor Green
                    $upgradeSd = Read-Host "Upgrade Scan Detector to version $sourceSdVersion? (y/n)"
                    if ($upgradeSd -eq "y" -or $upgradeSd -eq "Y") {
                        Copy-Item $scanDetectorSource $scanDetectorDest -Force
                        Write-Host "[+] Upgraded scan_detector.lua to version $sourceSdVersion" -ForegroundColor Green
                        $versionHandled = $true
                    } else {
                        Write-Host "Skipping Scan Detector upgrade." -ForegroundColor Yellow
                        $versionHandled = $true
                    }
                } elseif ($sourceSdVer -eq $installedSdVer) {
                    Write-Host "[+] Scan Detector already installed (version $installedSdVersion)" -ForegroundColor Green
                    $reinstallSd = Read-Host "Reinstall Scan Detector? (y/n)"
                    if ($reinstallSd -eq "y" -or $reinstallSd -eq "Y") {
                        Copy-Item $scanDetectorSource $scanDetectorDest -Force
                        Write-Host "[+] Reinstalled scan_detector.lua" -ForegroundColor Green
                        $versionHandled = $true
                    } else {
                        $versionHandled = $true
                    }
                } else {
                    # Installed version is newer, skip
                    $versionHandled = $true
                }
            } catch {
                # Version parsing failed, fall through to timestamp check
                $versionHandled = $false
            }
            
            # Fallback to timestamp comparison if version comparison didn't result in action
            if (-not $versionHandled) {
                $installedSdTime = (Get-Item $scanDetectorDest).LastWriteTime
                $sourceSdTime = (Get-Item $scanDetectorSource).LastWriteTime
                if ($sourceSdTime -gt $installedSdTime) {
                    Write-Host "[*] Scan Detector newer version available" -ForegroundColor Cyan
                    $upgradeSd = Read-Host "Upgrade Scan Detector? (y/n)"
                    if ($upgradeSd -eq "y" -or $upgradeSd -eq "Y") {
                        Copy-Item $scanDetectorSource $scanDetectorDest -Force
                        Write-Host "[+] Upgraded scan_detector.lua" -ForegroundColor Green
                    }
                }
            }
        } else {
            # Fallback to timestamp comparison
            $installedSdTime = (Get-Item $scanDetectorDest).LastWriteTime
            $sourceSdTime = (Get-Item $scanDetectorSource).LastWriteTime
            if ($sourceSdTime -gt $installedSdTime) {
                Write-Host "[*] Scan Detector newer version available" -ForegroundColor Cyan
                $upgradeSd = Read-Host "Upgrade Scan Detector? (y/n)"
                if ($upgradeSd -eq "y" -or $upgradeSd -eq "Y") {
                    Copy-Item $scanDetectorSource $scanDetectorDest -Force
                    Write-Host "[+] Upgraded scan_detector.lua" -ForegroundColor Green
                }
            } else {
                $installScanDetector = Read-Host "Install Scan Detector plugin? (y/n)"
                if ($installScanDetector -eq "y" -or $installScanDetector -eq "Y") {
                    Copy-Item $scanDetectorSource $scanDetectorDest -Force
                    Write-Host "[+] Installed scan_detector.lua" -ForegroundColor Green
                }
            }
        }
    } else {
        $installScanDetector = Read-Host "Install Scan Detector plugin? (y/n)"
        if ($installScanDetector -eq "y" -or $installScanDetector -eq "Y") {
            Copy-Item $scanDetectorSource $scanDetectorDest -Force
            $sourceSdVersion = Extract-Version -FilePath $scanDetectorSource
            if ($sourceSdVersion) {
                Write-Host "[+] Installed scan_detector.lua version $sourceSdVersion" -ForegroundColor Green
            } else {
                Write-Host "[+] Installed scan_detector.lua" -ForegroundColor Green
            }
        }
    }
} else {
    Write-Host "[!] scan_detector.lua not found in Scan_Detector directory" -ForegroundColor Yellow
}

# Comprehensive dependency check
Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Dependency Check - External Tools" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Checking for external tools required by ASK features..." -ForegroundColor Cyan
Write-Host ""

# Define dependencies with their purposes
$dependencies = @{
    "openssl" = "Certificate Validity Check"
    "nmap" = "Network Scanning (SYN Scan, Service Scan, Vulners Scan)"
    "ping" = "Ping feature"
    "tracert" = "Traceroute feature"
    "dig" = "DNS Analytics (preferred)"
    "nslookup" = "DNS Analytics (fallback - usually pre-installed)"
    "curl" = "API requests (all threat intelligence APIs)"
}

# Track missing and available dependencies
$missingDeps = @()
$availableDeps = @()

# Check each dependency
foreach ($tool in $dependencies.Keys) {
    $cmd = Get-Command $tool -ErrorAction SilentlyContinue
    if ($cmd) {
        Write-Host "[+] $tool - Found" -ForegroundColor Green
        Write-Host "    Purpose: $($dependencies[$tool])" -ForegroundColor Gray
        $availableDeps += $tool
    } else {
        Write-Host "[!] $tool - NOT FOUND" -ForegroundColor Yellow
        Write-Host "    Purpose: $($dependencies[$tool])" -ForegroundColor Gray
        $missingDeps += $tool
    }
}

# Show installation instructions for missing dependencies
if ($missingDeps.Count -gt 0) {
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "Installation Instructions for Missing Tools" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($tool in $missingDeps) {
        switch ($tool) {
            "openssl" {
                Write-Host "[!] OpenSSL - Required for Certificate Validity Check" -ForegroundColor Yellow
                Write-Host "    Download: https://slproweb.com/products/Win32OpenSSL.html" -ForegroundColor Cyan
                Write-Host "    Chocolatey: choco install openssl" -ForegroundColor Cyan
                Write-Host "    Git for Windows: Includes OpenSSL (https://git-scm.com/download/win)" -ForegroundColor Cyan
                Write-Host "    Note: Add OpenSSL to your system PATH after installation" -ForegroundColor Gray
            }
            "nmap" {
                Write-Host "[!] Nmap - Required for Network Scanning features" -ForegroundColor Yellow
                Write-Host "    Download: https://nmap.org/download.html" -ForegroundColor Cyan
                Write-Host "    Chocolatey: choco install nmap" -ForegroundColor Cyan
                Write-Host "    Note: Some scans require administrator privileges" -ForegroundColor Gray
            }
            "ping" {
                Write-Host "[!] Ping - Required for Ping feature" -ForegroundColor Yellow
                Write-Host "    Status: Usually pre-installed on Windows" -ForegroundColor Gray
                Write-Host "    If missing, ping is part of Windows system tools" -ForegroundColor Gray
            }
            "tracert" {
                Write-Host "[!] Tracert - Required for Traceroute feature" -ForegroundColor Yellow
                Write-Host "    Status: Usually pre-installed on Windows" -ForegroundColor Gray
                Write-Host "    If missing, tracert is part of Windows system tools" -ForegroundColor Gray
            }
            "dig" {
                Write-Host "[!] Dig - Required for DNS Analytics (preferred tool)" -ForegroundColor Yellow
                Write-Host "    Download: https://www.isc.org/download/" -ForegroundColor Cyan
                Write-Host "    Chocolatey: choco install bind-toolsonly" -ForegroundColor Cyan
                Write-Host "    WSL: Use Windows Subsystem for Linux (includes dig)" -ForegroundColor Cyan
                Write-Host "    Note: nslookup (fallback) is usually pre-installed on Windows" -ForegroundColor Gray
            }
            "nslookup" {
                Write-Host "[!] Nslookup - Required for DNS Analytics (fallback)" -ForegroundColor Yellow
                Write-Host "    Status: Usually pre-installed on Windows" -ForegroundColor Gray
                Write-Host "    If missing, install BIND tools or use WSL" -ForegroundColor Gray
            }
            "curl" {
                Write-Host "[!] Curl - Required for all API requests" -ForegroundColor Yellow
                Write-Host "    Status: Usually pre-installed on Windows 10+" -ForegroundColor Gray
                Write-Host "    Download: https://curl.se/windows/" -ForegroundColor Cyan
                Write-Host "    Chocolatey: choco install curl" -ForegroundColor Cyan
            }
        }
        Write-Host ""
    }
    
    Write-Host "After installing missing tools, restart Wireshark for changes to take effect." -ForegroundColor Yellow
    Write-Host ""
    
    # Show feature availability summary
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "Feature Availability Summary" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Based on installed tools, the following features are available:" -ForegroundColor Cyan
    Write-Host ""
    
    if ($availableDeps -contains "curl") {
        Write-Host "[+] API-based Features: Available" -ForegroundColor Green
        Write-Host "    - IP Reputation (AbuseIPDB, VirusTotal)" -ForegroundColor Gray
        Write-Host "    - IP Intelligence (Shodan, IPinfo, GreyNoise)" -ForegroundColor Gray
        Write-Host "    - Threat Intelligence (AlienVault OTX, Abuse.ch)" -ForegroundColor Gray
        Write-Host "    - URL Analysis (urlscan.io, VirusTotal)" -ForegroundColor Gray
        Write-Host "    - Certificate Transparency (crt.sh)" -ForegroundColor Gray
    } else {
        Write-Host "[!] API-based Features: UNAVAILABLE (curl required)" -ForegroundColor Yellow
    }
    
    if ($availableDeps -contains "openssl") {
        Write-Host "[+] Certificate Validity Check: Available" -ForegroundColor Green
    } else {
        Write-Host "[!] Certificate Validity Check: UNAVAILABLE (openssl required)" -ForegroundColor Yellow
    }
    
    if ($availableDeps -contains "dig" -or $availableDeps -contains "nslookup") {
        Write-Host "[+] DNS Analytics: Available" -ForegroundColor Green
    } else {
        Write-Host "[!] DNS Analytics: UNAVAILABLE (dig or nslookup required)" -ForegroundColor Yellow
    }
    
    if ($availableDeps -contains "ping") {
        Write-Host "[+] Ping: Available" -ForegroundColor Green
    } else {
        Write-Host "[!] Ping: UNAVAILABLE (ping required)" -ForegroundColor Yellow
    }
    
    if ($availableDeps -contains "tracert") {
        Write-Host "[+] Traceroute: Available" -ForegroundColor Green
    } else {
        Write-Host "[!] Traceroute: UNAVAILABLE (tracert required)" -ForegroundColor Yellow
    }
    
    if ($availableDeps -contains "nmap") {
        Write-Host "[+] Network Scanning (Nmap): Available" -ForegroundColor Green
        Write-Host "    - SYN Scan" -ForegroundColor Gray
        Write-Host "    - Service Scan" -ForegroundColor Gray
        Write-Host "    - Vulners Vulnerability Scan" -ForegroundColor Gray
    } else {
        Write-Host "[!] Network Scanning (Nmap): UNAVAILABLE (nmap required)" -ForegroundColor Yellow
    }
    
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "[+] All external tools are available!" -ForegroundColor Green
    Write-Host ""
    Write-Host "All ASK features are fully functional:" -ForegroundColor Green
    Write-Host "  - API-based threat intelligence lookups" -ForegroundColor Gray
    Write-Host "  - Certificate Validity Check" -ForegroundColor Gray
    Write-Host "  - DNS Analytics" -ForegroundColor Gray
    Write-Host "  - Network diagnostics (Ping, Traceroute)" -ForegroundColor Gray
    Write-Host "  - Network scanning (Nmap)" -ForegroundColor Gray
    Write-Host ""
}

# Offer to install JSON library (check for curl/Invoke-WebRequest first)
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "JSON Library Installation (Recommended)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
$hasDownloadTool = $false
$downloadTool = ""

# Check for download tools
# Note: On Windows, 'curl' is often a PowerShell alias for Invoke-WebRequest
# which doesn't support Unix curl flags, so we'll use Invoke-WebRequest directly
if (Get-Command Invoke-WebRequest -ErrorAction SilentlyContinue) {
    # PowerShell's Invoke-WebRequest is always available on Windows
    $hasDownloadTool = $true
    $downloadTool = "Invoke-WebRequest"
} elseif (Get-Command curl.exe -ErrorAction SilentlyContinue) {
    # Check for actual curl.exe (not the PowerShell alias)
    $hasDownloadTool = $true
    $downloadTool = "curl.exe"
}

if ($hasDownloadTool) {
    Write-Host "The JSON library significantly improves parsing performance for:" -ForegroundColor Cyan
    Write-Host "  - urlscan.io search results" -ForegroundColor Cyan
    Write-Host "  - Complex JSON responses from all APIs" -ForegroundColor Cyan
    Write-Host "  - Nested arrays and objects" -ForegroundColor Cyan
    Write-Host ""
    $installJson = Read-Host "Install JSON library? (y/n)"
    if ($installJson -eq "y" -or $installJson -eq "Y") {
        $jsonUrl = "https://raw.githubusercontent.com/rxi/json.lua/master/json.lua"
        $jsonDest = Join-Path $PLUGINS_DIR "json.lua"
        try {
            if ($downloadTool -eq "Invoke-WebRequest") {
                Invoke-WebRequest -Uri $jsonUrl -OutFile $jsonDest -UseBasicParsing
            } elseif ($downloadTool -eq "curl.exe") {
                # Use curl.exe with Windows-compatible flags
                & curl.exe -L -o $jsonDest $jsonUrl
            } else {
                Invoke-WebRequest -Uri $jsonUrl -OutFile $jsonDest -UseBasicParsing
            }
            if (Test-Path $jsonDest) {
                Write-Host "[+] Installed json.lua" -ForegroundColor Green
                Write-Host ""
                Write-Host "The JSON library improves parsing for:" -ForegroundColor Cyan
                Write-Host "  - urlscan.io search results" -ForegroundColor Cyan
                Write-Host '  - Complex JSON responses from all APIs (AbuseIPDB, VirusTotal, Shodan, etc.)' -ForegroundColor Cyan
                Write-Host "  - Nested arrays and objects" -ForegroundColor Cyan
            } else {
                Write-Host "[!] Failed to download json.lua" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "[!] Failed to download json.lua: $_" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "[!] curl not found - cannot auto-install JSON library" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "The JSON library improves parsing performance for:" -ForegroundColor Cyan
    Write-Host "  - urlscan.io search results" -ForegroundColor Cyan
    Write-Host '  - Complex JSON responses from all APIs (AbuseIPDB, VirusTotal, Shodan, IPinfo, GreyNoise, OTX, Abuse.ch)' -ForegroundColor Cyan
    Write-Host "  - Nested arrays and objects" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "To install manually:" -ForegroundColor Yellow
    Write-Host "1. curl is usually pre-installed on Windows 10+" -ForegroundColor Yellow
    Write-Host "2. If not available, download from:" -ForegroundColor Yellow
    Write-Host "   https://raw.githubusercontent.com/rxi/json.lua/master/json.lua" -ForegroundColor Yellow
    Write-Host "3. Save to: $PLUGINS_DIR\json.lua" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "See INSTALL_JSON_LIBRARY.md for detailed instructions." -ForegroundColor Yellow
}

# Offer to run API key setup
Write-Host ""
$runSetup = Read-Host "Run API key setup script? (y/n)"
if ($runSetup -eq "y" -or $runSetup -eq "Y") {
    $setupScript = Join-Path $SCRIPT_DIR "setup_api_keys.bat"
    if (Test-Path $setupScript) {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "`"$setupScript`"" -Wait -NoNewWindow
    } else {
        Write-Host "[!] setup_api_keys.bat not found in installer directory" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Installation complete!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:"
Write-Host "1. Restart Wireshark to load the plugin"
Write-Host '2. Right-click on a packet field -> ASK -> [Feature]'
Write-Host ""
Write-Host "For more information, see:"
Write-Host "- README.md in this directory"
Write-Host "- https://github.com/netwho/ask"
Write-Host ""
