# Quick install script for json.lua library for Wireshark (Windows PowerShell)

Write-Host "Installing json.lua for Wireshark..." -ForegroundColor Cyan
Write-Host ""

# Determine Wireshark plugins directory
$PluginsDir = Join-Path $env:APPDATA "Wireshark\plugins"

# Create plugins directory if it doesn't exist
if (-not (Test-Path $PluginsDir)) {
    New-Item -ItemType Directory -Path $PluginsDir -Force | Out-Null
}

# Download json.lua
Write-Host "Downloading json.lua from GitHub..." -ForegroundColor Yellow
try {
    $jsonUrl = "https://raw.githubusercontent.com/rxi/json.lua/master/json.lua"
    $jsonPath = Join-Path $PluginsDir "json.lua"
    
    Invoke-WebRequest -Uri $jsonUrl -OutFile $jsonPath -UseBasicParsing
    
    if (Test-Path $jsonPath) {
        Write-Host "✓ Successfully installed json.lua to: $jsonPath" -ForegroundColor Green
        Write-Host ""
        Write-Host "Next steps:" -ForegroundColor Cyan
        Write-Host "1. Restart Wireshark"
        Write-Host "2. The ASK (Analyst's Shark Knife) plugin will automatically use the JSON library"
        Write-Host "3. Check Wireshark console for: 'JSON library successfully parsed response'"
        Write-Host ""
        Write-Host "This will improve parsing of:" -ForegroundColor Yellow
        Write-Host "  - urlscan.io search results"
        Write-Host "  - Complex JSON responses from all APIs"
        Write-Host "  - Nested arrays and objects"
    } else {
        Write-Host "✗ Failed to download json.lua" -ForegroundColor Red
        Write-Host "Please install manually - see INSTALL_JSON_LIBRARY.md" -ForegroundColor Yellow
        exit 1
    }
} catch {
    Write-Host "✗ Error downloading json.lua: $_" -ForegroundColor Red
    Write-Host "Please install manually - see INSTALL_JSON_LIBRARY.md" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
