# Setup script for ASK (Analyst's Shark Knife) API keys (Windows PowerShell)
# This creates the %USERPROFILE%\.ask directory and helps you set up API key files

$ConfigDir = Join-Path $env:USERPROFILE ".ask"

# Create config directory if it doesn't exist
if (-not (Test-Path $ConfigDir)) {
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
}

Write-Host "ASK (Analyst's Shark Knife) API Key Setup" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This script will help you set up API keys for ASK."
Write-Host "API keys will be stored in: $ConfigDir"
Write-Host ""
Write-Host "Press Enter to skip any API key you don't want to configure."
Write-Host ""

# Function to prompt for API key
function Prompt-ApiKey {
    param(
        [string]$ServiceName,
        [string]$FileName,
        [string]$Url,
        [string]$Required  # "required" or "optional"
    )
    
    Write-Host "----------------------------------------" -ForegroundColor Gray
    Write-Host "[$ServiceName]" -ForegroundColor Yellow
    
    $FilePath = Join-Path $ConfigDir $FileName
    
    if (Test-Path $FilePath) {
        Write-Host "✓ API key file already exists: $FileName" -ForegroundColor Green
        $UpdateChoice = Read-Host "Update this key? (y/N)"
        if ($UpdateChoice -ne "y" -and $UpdateChoice -ne "Y") {
            Write-Host "Skipping $ServiceName..." -ForegroundColor Gray
            Write-Host ""
            return
        }
    }
    
    if ($Required -eq "required") {
        Write-Host "Get your free API key at: $Url" -ForegroundColor Cyan
        $ApiKey = Read-Host "Enter $ServiceName API Key"
    } else {
        Write-Host "Optional - Get your free API key at: $Url" -ForegroundColor Cyan
        $ApiKey = Read-Host "Enter $ServiceName API Key (or press Enter to skip)"
    }
    
    if ($ApiKey -and $ApiKey.Trim() -ne "") {
        $ApiKey.Trim() | Out-File -FilePath $FilePath -Encoding UTF8 -NoNewline
        # Set file permissions (Windows equivalent of chmod 600)
        $acl = Get-Acl $FilePath
        $acl.SetAccessRuleProtection($true, $false)
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($env:USERNAME, "FullControl", "Allow")
        $acl.SetAccessRule($accessRule)
        Set-Acl -Path $FilePath -AclObject $acl
        Write-Host "✓ $ServiceName API key saved" -ForegroundColor Green
    } else {
        if ($Required -eq "required") {
            Write-Host "⚠ Warning: $ServiceName API key is required but was not provided" -ForegroundColor Yellow
        } else {
            Write-Host "Skipped $ServiceName (optional)" -ForegroundColor Gray
        }
    }
    Write-Host ""
}

# Prompt for each API key separately
Prompt-ApiKey -ServiceName "AbuseIPDB" -FileName "ABUSEIPDB_API_KEY.txt" -Url "https://www.abuseipdb.com/api" -Required "required"

Prompt-ApiKey -ServiceName "VirusTotal" -FileName "VIRUSTOTAL_API_KEY.txt" -Url "https://www.virustotal.com/gui/join-us" -Required "optional"

Prompt-ApiKey -ServiceName "Shodan" -FileName "SHODAN_API_KEY.txt" -Url "https://account.shodan.io/register" -Required "optional"

Prompt-ApiKey -ServiceName "IPinfo" -FileName "IPINFO_API_KEY.txt" -Url "https://ipinfo.io/signup" -Required "optional"

Prompt-ApiKey -ServiceName "urlscan.io" -FileName "URLSCAN_API_KEY.txt" -Url "https://urlscan.io/user/signup" -Required "optional"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Setup complete! API keys are stored in $ConfigDir" -ForegroundColor Green
Write-Host ""
Write-Host "Summary of configured keys:" -ForegroundColor Cyan

$Keys = @(
    @{Name="AbuseIPDB"; File="ABUSEIPDB_API_KEY.txt"},
    @{Name="VirusTotal"; File="VIRUSTOTAL_API_KEY.txt"},
    @{Name="Shodan"; File="SHODAN_API_KEY.txt"},
    @{Name="IPinfo"; File="IPINFO_API_KEY.txt"},
    @{Name="urlscan.io"; File="URLSCAN_API_KEY.txt"}
)

foreach ($Key in $Keys) {
    $FilePath = Join-Path $ConfigDir $Key.File
    if (Test-Path $FilePath) {
        Write-Host "  ✓ $($Key.Name)" -ForegroundColor Green
    } else {
        if ($Key.Name -eq "AbuseIPDB") {
            Write-Host "  ✗ $($Key.Name) (not configured)" -ForegroundColor Red
        } else {
            Write-Host "  ✗ $($Key.Name) (optional)" -ForegroundColor Gray
        }
    }
}

Write-Host ""
Write-Host "Restart Wireshark for changes to take effect." -ForegroundColor Yellow
Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
