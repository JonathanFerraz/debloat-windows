@echo off
:: ==============================================
:: Windows Debloat & Optimization Script
:: Version: 3.0 | Date: 2025-04-27
:: ==============================================
:: Description:
:: This script performs complete debloating, optimizations,
:: and privacy settings adjustments on Windows.
:: ==============================================

:: ----------------------------
:: Administrator Check
:: ----------------------------
NET FILE > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] This script requires administrator privileges.
    echo Please run as Administrator and try again.
    echo.
    pause
    exit /b
)

:: ----------------------------
:: Initial Settings
:: ----------------------------
setlocal EnableDelayedExpansion
color 0a
title Ryzen Windows Debloat Tool v3.0
echo.
echo ==============================================
echo STARTING OPTIMIZATION PROCESS
echo ==============================================

:: ---------------------------------
:: 1. Create a Restore Point
:: ---------------------------------
echo.
echo [STEP 1/8] Creating a restore point...
powershell -command "Enable-ComputerRestore -Drive $env:SystemDrive"
powershell -command "Checkpoint-Computer -Description 'Pre-Debloat' -RestorePointType 'MODIFY_SETTINGS'"
if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] Restore point created.
) else (
    echo [WARNING] Failed to create restore point.
)

:: ----------------------------
:: 2. System Cleanup
:: ----------------------------
echo.
echo [STEP 2/8] Performing system cleanup...
call "%~dp0assets\remove-temp.bat"
echo.
echo Running Disk Cleanup...
cleanmgr /verylowdisk /sagerun:5
echo.
echo Checking system integrity...
sfc /scannow

:: ----------------------------
:: 3. App Removal
:: ----------------------------
echo.
echo [STEP 3/8] Removing unnecessary apps...
call "%~dp0assets\remove-apps.bat"
call "%~dp0assets\remove-edge.bat"
call "%~dp0assets\ms-gamebar-annoyance.bat"

:: ----------------------------
:: 4. Network Optimizations
:: ----------------------------
echo.
echo [STEP 4/8] Optimizing network settings...
echo Resetting TCP/IP settings...
ipconfig /flushdns
ipconfig /release
ipconfig /renew
netsh interface ip set dns name="Ethernet" static 8.8.8.8
netsh interface ip add dns name="Ethernet" 8.8.4.4 index=2
netsh int tcp set global rss=disabled
netsh int tcp set global autotuninglevel=restricted

:: ----------------------------
:: 5. Disabling Features
:: ----------------------------
echo.
echo [STEP 5/8] Disabling Windows features...
echo Disabling Internet Explorer...
dism /online /Remove-Capability /CapabilityName:Browser.InternetExplorer~~~~0.0.11.0 /NoRestart

echo Disabling Hyper-V...
dism /online /Disable-Feature /FeatureName:Microsoft-Hyper-V-All /NoRestart

echo Disabling Windows Media Player...
dism /online /Disable-Feature /FeatureName:WindowsMediaPlayer /NoRestart

echo Disabling Recall...
DISM /Online /Disable-Feature /FeatureName:Recall /NoRestart

:: ----------------------------
:: 6. System Settings
:: ----------------------------
echo.
echo [STEP 6/8] Applying system optimizations...
call "%~dp0assets\registry.bat"
call "%~dp0services.bat"
call "%~dp0assets\telemetry.bat"

:: ----------------------------
:: 7. Power Settings
:: ----------------------------
echo.
echo [STEP 7/8] Configuring power plan...
echo Activating Ultimate Performance mode...
powershell -command "$scheme = powercfg -list | Select-String 'Ultimate Performance'; if (-not $scheme) { powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 }"
for /f "tokens=2 delims=:(" %%i in ('powercfg -list ^| findstr "Ultimate Performance"') do (
    powercfg -setactive %%i
)
echo Disabling hibernation...
powercfg /hibernate off

:: ----------------------------
:: 8. Finalization
:: ----------------------------
echo.
echo [STEP 8/8] Finalizing optimizations...
:: Check system integrity
sfc /scannow

:: Optimize storage
defrag C: /O /U

:: Restart critical services
net stop "Windows Audio" & net start "Windows Audio"

:: ----------------------------
:: Conclusion
:: ----------------------------
echo.
echo ==============================================
echo OPTIMIZATION COMPLETED SUCCESSFULLY!
echo ==============================================
echo.
echo Recommendations:
echo 1. Restart your computer.
echo 2. Check if all drivers are updated.
echo 3. Configure your essential programs.
echo.
echo Notes:
echo - Some changes require a restart.
echo - Removed features will no longer be available.
echo.
pause

:: Restart Explorer to apply changes
taskkill /f /im explorer.exe >nul
start explorer.exe
exit /b 0
