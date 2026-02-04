@echo off
REM ASK (Analyst's Shark Knife) Installation Script Launcher
REM This wrapper bypasses PowerShell execution policy for network shares

echo Launching ASK installer...
echo.

REM Get the directory where this batch file is located
set "SCRIPT_DIR=%~dp0"

REM Run the PowerShell installer with execution policy bypass
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%SCRIPT_DIR%install.ps1"

REM If PowerShell fails, show error
if %ERRORLEVEL% neq 0 (
    echo.
    echo [!] Installation encountered an error.
    echo.
    pause
)
