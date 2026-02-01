@echo off
REM Setup script for ASK (Analyst's Shark Knife) API keys (Windows Batch)
REM This creates the %USERPROFILE%\.ask directory and helps you set up API key files

setlocal enabledelayedexpansion

set "CONFIG_DIR=%USERPROFILE%\.ask"

REM Create config directory if it doesn't exist
if not exist "%CONFIG_DIR%" mkdir "%CONFIG_DIR%"

echo ASK (Analyst's Shark Knife) API Key Setup
echo ==========================================
echo.
echo This script will help you set up API keys for ASK.
echo API keys will be stored in: %CONFIG_DIR%
echo.
echo Press Enter to skip any API key you don't want to configure.
echo.

REM AbuseIPDB
echo ----------------------------------------
echo [AbuseIPDB]
if exist "%CONFIG_DIR%\ABUSEIPDB_API_KEY.txt" (
    echo ✓ API key file already exists: ABUSEIPDB_API_KEY.txt
    set /p UPDATE_CHOICE="Update this key? (y/N): "
    if /i not "!UPDATE_CHOICE!"=="y" (
        echo Skipping AbuseIPDB...
        echo.
        goto :virustotal
    )
)
echo Get your free API key at: https://www.abuseipdb.com/api
set /p ABUSEIPDB_KEY="Enter AbuseIPDB API Key: "
if not "!ABUSEIPDB_KEY!"=="" (
    echo !ABUSEIPDB_KEY! > "%CONFIG_DIR%\ABUSEIPDB_API_KEY.txt"
    echo ✓ AbuseIPDB API key saved
) else (
    echo ⚠ Warning: AbuseIPDB API key is required but was not provided
)
echo.

:virustotal
REM VirusTotal
echo ----------------------------------------
echo [VirusTotal]
if exist "%CONFIG_DIR%\VIRUSTOTAL_API_KEY.txt" (
    echo ✓ API key file already exists: VIRUSTOTAL_API_KEY.txt
    set /p UPDATE_CHOICE="Update this key? (y/N): "
    if /i not "!UPDATE_CHOICE!"=="y" (
        echo Skipping VirusTotal...
        echo.
        goto :shodan
    )
)
echo Optional - Get your free API key at: https://www.virustotal.com/gui/join-us
set /p VIRUSTOTAL_KEY="Enter VirusTotal API Key (or press Enter to skip): "
if not "!VIRUSTOTAL_KEY!"=="" (
    echo !VIRUSTOTAL_KEY! > "%CONFIG_DIR%\VIRUSTOTAL_API_KEY.txt"
    echo ✓ VirusTotal API key saved
) else (
    echo Skipped VirusTotal (optional)
)
echo.

:shodan
REM Shodan
echo ----------------------------------------
echo [Shodan]
if exist "%CONFIG_DIR%\SHODAN_API_KEY.txt" (
    echo ✓ API key file already exists: SHODAN_API_KEY.txt
    set /p UPDATE_CHOICE="Update this key? (y/N): "
    if /i not "!UPDATE_CHOICE!"=="y" (
        echo Skipping Shodan...
        echo.
        goto :ipinfo
    )
)
echo Optional - Get your free API key at: https://account.shodan.io/register
set /p SHODAN_KEY="Enter Shodan API Key (or press Enter to skip): "
if not "!SHODAN_KEY!"=="" (
    echo !SHODAN_KEY! > "%CONFIG_DIR%\SHODAN_API_KEY.txt"
    echo ✓ Shodan API key saved
) else (
    echo Skipped Shodan (optional)
)
echo.

:ipinfo
REM IPinfo
echo ----------------------------------------
echo [IPinfo]
if exist "%CONFIG_DIR%\IPINFO_API_KEY.txt" (
    echo ✓ API key file already exists: IPINFO_API_KEY.txt
    set /p UPDATE_CHOICE="Update this key? (y/N): "
    if /i not "!UPDATE_CHOICE!"=="y" (
        echo Skipping IPinfo...
        echo.
        goto :urlscan
    )
)
echo Optional - Get your free API key at: https://ipinfo.io/signup
set /p IPINFO_KEY="Enter IPinfo API Key (or press Enter to skip): "
if not "!IPINFO_KEY!"=="" (
    echo !IPINFO_KEY! > "%CONFIG_DIR%\IPINFO_API_KEY.txt"
    echo ✓ IPinfo API key saved
) else (
    echo Skipped IPinfo (optional)
)
echo.

:urlscan
REM urlscan.io
echo ----------------------------------------
echo [urlscan.io]
if exist "%CONFIG_DIR%\URLSCAN_API_KEY.txt" (
    echo ✓ API key file already exists: URLSCAN_API_KEY.txt
    set /p UPDATE_CHOICE="Update this key? (y/N): "
    if /i not "!UPDATE_CHOICE!"=="y" (
        echo Skipping urlscan.io...
        echo.
        goto :summary
    )
)
echo Optional - Get your free API key at: https://urlscan.io/user/signup
set /p URLSCAN_KEY="Enter urlscan.io API Key (or press Enter to skip): "
if not "!URLSCAN_KEY!"=="" (
    echo !URLSCAN_KEY! > "%CONFIG_DIR%\URLSCAN_API_KEY.txt"
    echo ✓ urlscan.io API key saved
) else (
    echo Skipped urlscan.io (optional)
)
echo.

:summary
echo ========================================
echo Setup complete! API keys are stored in %CONFIG_DIR%
echo.
echo Summary of configured keys:

if exist "%CONFIG_DIR%\ABUSEIPDB_API_KEY.txt" (
    echo   ✓ AbuseIPDB
) else (
    echo   ✗ AbuseIPDB (not configured)
)

if exist "%CONFIG_DIR%\VIRUSTOTAL_API_KEY.txt" (
    echo   ✓ VirusTotal
) else (
    echo   ✗ VirusTotal (optional)
)

if exist "%CONFIG_DIR%\SHODAN_API_KEY.txt" (
    echo   ✓ Shodan
) else (
    echo   ✗ Shodan (optional)
)

if exist "%CONFIG_DIR%\IPINFO_API_KEY.txt" (
    echo   ✓ IPinfo
) else (
    echo   ✗ IPinfo (optional)
)

if exist "%CONFIG_DIR%\URLSCAN_API_KEY.txt" (
    echo   ✓ urlscan.io
) else (
    echo   ✗ urlscan.io (optional)
)

echo.
echo Restart Wireshark for changes to take effect.
echo.
pause

endlocal
