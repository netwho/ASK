# ASK (Analyst's Shark Knife) Installation Script for Windows
# Version: 0.2.1

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "ASK (Analyst's Shark Knife) Installer" -ForegroundColor Cyan
Write-Host "Version 0.2.1 - Windows" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Wireshark is installed
$wiresharkPath = Get-Command wireshark -ErrorAction SilentlyContinue
if (-not $wiresharkPath) {
    Write-Host "⚠️  Wireshark is not found in PATH." -ForegroundColor Yellow
    Write-Host "   Please install Wireshark from https://www.wireshark.org/" -ForegroundColor Yellow
    exit 1
}

# Get Wireshark version
try {
    $versionOutput = & wireshark -v 2>&1 | Select-Object -First 1
    $versionMatch = $versionOutput -match '(\d+\.\d+)'
    if ($versionMatch) {
        $WIRESHARK_VERSION = $matches[1]
        Write-Host "✓ Found Wireshark version: $WIRESHARK_VERSION" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Could not determine Wireshark version" -ForegroundColor Yellow
    }
} catch {
    Write-Host "⚠️  Could not check Wireshark version" -ForegroundColor Yellow
}

# Create plugins directory
$PLUGINS_DIR = "$env:APPDATA\Wireshark\plugins"
if (-not (Test-Path $PLUGINS_DIR)) {
    New-Item -ItemType Directory -Path $PLUGINS_DIR -Force | Out-Null
}
Write-Host "✓ Created plugins directory: $PLUGINS_DIR" -ForegroundColor Green

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
                Write-Host "📦 Existing installation detected:" -ForegroundColor Cyan
                Write-Host "   Installed version: $installedVersion" -ForegroundColor Yellow
                Write-Host "   Available version: $sourceVersion" -ForegroundColor Green
                $upgrade = Read-Host "Upgrade to version $sourceVersion? (y/n)"
                if ($upgrade -ne "y" -and $upgrade -ne "Y") {
                    Write-Host "Skipping upgrade. Installation cancelled." -ForegroundColor Yellow
                    exit 0
                }
            } elseif ($sourceVer -eq $installedVer) {
                Write-Host "✓ Already installed version $installedVersion" -ForegroundColor Green
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
                Write-Host "📦 Existing installation detected (newer source file found)" -ForegroundColor Cyan
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
            Write-Host "✓ Installed ask.lua version $sourceVersion" -ForegroundColor Green
        } else {
            Write-Host "✓ Installed ask.lua" -ForegroundColor Green
        }
    } else {
        Write-Host "⚠️  ask.lua not found in installer directory" -ForegroundColor Yellow
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
            try {
                $installedSdVer = [Version]$installedSdVersion
                $sourceSdVer = [Version]$sourceSdVersion
                
                if ($sourceSdVer -gt $installedSdVer) {
                    Write-Host "📦 Scan Detector already installed:" -ForegroundColor Cyan
                    Write-Host "   Installed version: $installedSdVersion" -ForegroundColor Yellow
                    Write-Host "   Available version: $sourceSdVersion" -ForegroundColor Green
                    $upgradeSd = Read-Host "Upgrade Scan Detector to version $sourceSdVersion? (y/n)"
                    if ($upgradeSd -eq "y" -or $upgradeSd -eq "Y") {
                        Copy-Item $scanDetectorSource $scanDetectorDest -Force
                        Write-Host "✓ Upgraded scan_detector.lua to version $sourceSdVersion" -ForegroundColor Green
                    } else {
                        Write-Host "Skipping Scan Detector upgrade." -ForegroundColor Yellow
                    }
                } elseif ($sourceSdVer -eq $installedSdVer) {
                    Write-Host "✓ Scan Detector already installed (version $installedSdVersion)" -ForegroundColor Green
                    $reinstallSd = Read-Host "Reinstall Scan Detector? (y/n)"
                    if ($reinstallSd -eq "y" -or $reinstallSd -eq "Y") {
                        Copy-Item $scanDetectorSource $scanDetectorDest -Force
                        Write-Host "✓ Reinstalled scan_detector.lua" -ForegroundColor Green
                    }
                }
            } catch {
                # Version parsing failed, fall through to timestamp check
                $installedSdTime = (Get-Item $scanDetectorDest).LastWriteTime
                $sourceSdTime = (Get-Item $scanDetectorSource).LastWriteTime
                if ($sourceSdTime -gt $installedSdTime) {
                    Write-Host "📦 Scan Detector newer version available" -ForegroundColor Cyan
                    $upgradeSd = Read-Host "Upgrade Scan Detector? (y/n)"
                    if ($upgradeSd -eq "y" -or $upgradeSd -eq "Y") {
                        Copy-Item $scanDetectorSource $scanDetectorDest -Force
                        Write-Host "✓ Upgraded scan_detector.lua" -ForegroundColor Green
                    }
                } else {
                    $installScanDetector = Read-Host "Install Scan Detector plugin? (y/n)"
                    if ($installScanDetector -eq "y" -or $installScanDetector -eq "Y") {
                        Copy-Item $scanDetectorSource $scanDetectorDest -Force
                        Write-Host "✓ Installed scan_detector.lua" -ForegroundColor Green
                    }
                }
            }
        } else {
            # Fallback to timestamp comparison
            $installedSdTime = (Get-Item $scanDetectorDest).LastWriteTime
            $sourceSdTime = (Get-Item $scanDetectorSource).LastWriteTime
            if ($sourceSdTime -gt $installedSdTime) {
                Write-Host "📦 Scan Detector newer version available" -ForegroundColor Cyan
                $upgradeSd = Read-Host "Upgrade Scan Detector? (y/n)"
                if ($upgradeSd -eq "y" -or $upgradeSd -eq "Y") {
                    Copy-Item $scanDetectorSource $scanDetectorDest -Force
                    Write-Host "✓ Upgraded scan_detector.lua" -ForegroundColor Green
                }
            } else {
                $installScanDetector = Read-Host "Install Scan Detector plugin? (y/n)"
                if ($installScanDetector -eq "y" -or $installScanDetector -eq "Y") {
                    Copy-Item $scanDetectorSource $scanDetectorDest -Force
                    Write-Host "✓ Installed scan_detector.lua" -ForegroundColor Green
                }
            }
        }
    } else {
        $installScanDetector = Read-Host "Install Scan Detector plugin? (y/n)"
        if ($installScanDetector -eq "y" -or $installScanDetector -eq "Y") {
            Copy-Item $scanDetectorSource $scanDetectorDest -Force
            $sourceSdVersion = Extract-Version -FilePath $scanDetectorSource
            if ($sourceSdVersion) {
                Write-Host "✓ Installed scan_detector.lua version $sourceSdVersion" -ForegroundColor Green
            } else {
                Write-Host "✓ Installed scan_detector.lua" -ForegroundColor Green
            }
        }
    }
} else {
    Write-Host "⚠️  scan_detector.lua not found in Scan_Detector directory" -ForegroundColor Yellow
}

# Check for optional tools
Write-Host ""
Write-Host "Checking optional tools..." -ForegroundColor Cyan

# Check OpenSSL
$openssl = Get-Command openssl -ErrorAction SilentlyContinue
if ($openssl) {
    Write-Host "✓ openssl found" -ForegroundColor Green
} else {
    Write-Host "⚠️  openssl not found (required for Certificate Validity Check)" -ForegroundColor Yellow
    Write-Host "   Install options:" -ForegroundColor Yellow
    Write-Host "   - Git for Windows (includes OpenSSL)" -ForegroundColor Yellow
    Write-Host "   - Standalone: https://slproweb.com/products/Win32OpenSSL.html" -ForegroundColor Yellow
    Write-Host "   - Chocolatey: choco install openssl" -ForegroundColor Yellow
}

# Check dig
$dig = Get-Command dig -ErrorAction SilentlyContinue
if ($dig) {
    Write-Host "✓ dig found" -ForegroundColor Green
} else {
    Write-Host "⚠️  dig not found (required for DNS Analytics)" -ForegroundColor Yellow
    Write-Host "   Install options:" -ForegroundColor Yellow
    Write-Host "   - BIND Tools: https://www.isc.org/download/" -ForegroundColor Yellow
    Write-Host "   - WSL (Windows Subsystem for Linux)" -ForegroundColor Yellow
    Write-Host "   - Chocolatey: choco install bind-toolsonly" -ForegroundColor Yellow
}

# Check nmap
$nmap = Get-Command nmap -ErrorAction SilentlyContinue
if ($nmap) {
    Write-Host "✓ nmap found" -ForegroundColor Green
} else {
    Write-Host "⚠️  nmap not found (required for Network Scanning)" -ForegroundColor Yellow
    Write-Host "   Install options:" -ForegroundColor Yellow
    Write-Host "   - Official: https://nmap.org/download.html" -ForegroundColor Yellow
    Write-Host "   - Chocolatey: choco install nmap" -ForegroundColor Yellow
}

# Check curl
$curl = Get-Command curl -ErrorAction SilentlyContinue
if ($curl) {
    Write-Host "✓ curl found" -ForegroundColor Green
} else {
    Write-Host "⚠️  curl not found (required for API requests)" -ForegroundColor Yellow
    Write-Host "   Usually pre-installed on Windows 10+" -ForegroundColor Yellow
}

# Offer to install JSON library (check for curl/Invoke-WebRequest first)
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "📚 JSON Library Installation (Recommended)" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
$hasDownloadTool = $false
$downloadTool = ""

# Check for curl (Windows 10+ usually has it)
$curl = Get-Command curl -ErrorAction SilentlyContinue
if ($curl) {
    $hasDownloadTool = $true
    $downloadTool = "curl"
} elseif (Get-Command Invoke-WebRequest -ErrorAction SilentlyContinue) {
    # PowerShell's Invoke-WebRequest is always available
    $hasDownloadTool = $true
    $downloadTool = "Invoke-WebRequest"
}

if ($hasDownloadTool) {
    Write-Host "The JSON library significantly improves parsing performance for:" -ForegroundColor Cyan
    Write-Host "  • urlscan.io search results" -ForegroundColor Cyan
    Write-Host "  • Complex JSON responses from all APIs" -ForegroundColor Cyan
    Write-Host "  • Nested arrays and objects" -ForegroundColor Cyan
    Write-Host ""
    $installJson = Read-Host "Install JSON library? (y/n)"
    if ($installJson -eq "y" -or $installJson -eq "Y") {
        $jsonUrl = "https://raw.githubusercontent.com/rxi/json.lua/master/json.lua"
        $jsonDest = Join-Path $PLUGINS_DIR "json.lua"
        try {
            if ($downloadTool -eq "curl") {
                & curl -sSL $jsonUrl -o $jsonDest
            } else {
                Invoke-WebRequest -Uri $jsonUrl -OutFile $jsonDest -UseBasicParsing
            }
            if (Test-Path $jsonDest) {
                Write-Host "✓ Installed json.lua" -ForegroundColor Green
                Write-Host ""
                Write-Host "The JSON library improves parsing for:" -ForegroundColor Cyan
                Write-Host "  - urlscan.io search results" -ForegroundColor Cyan
                Write-Host "  - Complex JSON responses from all APIs (AbuseIPDB, VirusTotal, Shodan, etc.)" -ForegroundColor Cyan
                Write-Host "  - Nested arrays and objects" -ForegroundColor Cyan
            } else {
                Write-Host "⚠️  Failed to download json.lua" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "⚠️  Failed to download json.lua: $_" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "⚠️  curl not found - cannot auto-install JSON library" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "The JSON library improves parsing performance for:" -ForegroundColor Cyan
    Write-Host "  - urlscan.io search results" -ForegroundColor Cyan
    Write-Host "  - Complex JSON responses from all APIs (AbuseIPDB, VirusTotal, Shodan, IPinfo, GreyNoise, OTX, Abuse.ch)" -ForegroundColor Cyan
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
    $setupScript = Join-Path $SCRIPT_DIR "setup_api_keys.ps1"
    if (Test-Path $setupScript) {
        & $setupScript
    } else {
        Write-Host "⚠️  setup_api_keys.ps1 not found in installer directory" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Installation complete!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:"
Write-Host "1. Restart Wireshark to load the plugin"
Write-Host "2. Right-click on a packet field → ASK → [Feature]"
Write-Host ""
Write-Host "For more information, see:"
Write-Host "- README.md in this directory"
Write-Host "- https://github.com/netwho/ask"
Write-Host ""
