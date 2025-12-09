# ==============================================
# R Y Z Ξ N Optimizer
# Version: 2.0 | Date: 2025-07-25
# ==============================================
# Description:
# This script performs complete debloating, optimizations,
# and privacy settings adjustments on Windows.
# ==============================================

# ----------------------------
# Administrator Check
# ----------------------------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "`n[ERROR] This script requires administrator privileges." -ForegroundColor Red
    Write-Host "Please run as Administrator and try again.`n"
    Pause
    exit
}

# ----------------------------
# Initial Settings
# ----------------------------
$host.UI.RawUI.WindowTitle = "Ryzen Optimizer v2.0"
Write-Host ""
Write-Host "=============================================="
Write-Host "          STARTING OPTIMIZATION PROCESS       "
Write-Host "==============================================`n"

# ----------------------------
# 1. Create a Restore Point
# ----------------------------
Write-Host "[STEP 1/8] Creating a restore point..."
try {
    Enable-ComputerRestore -Drive $env:SystemDrive -ErrorAction Stop
    Checkpoint-Computer -Description 'Pre-Debloat' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
    Write-Host "[SUCCESS] Restore point created.`n"
} catch {
    Write-Warning "[WARNING] Failed to create restore point.`n"
}

# ----------------------------
# 2. System Cleanup
# ----------------------------
Write-Host "[STEP 2/8] Performing system cleanup..."
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Calling external batch scripts converted to PowerShell if available
$removeTempPath = Join-Path $scriptDir "scripts\cleanup\remove-temp.ps1"
if (Test-Path $removeTempPath) {
    powershell.exe -ExecutionPolicy Bypass -File "$removeTempPath"
}

Write-Host "`nRunning Disk Cleanup..."
cleanmgr /verylowdisk /sagerun:5

Write-Host "`nChecking system integrity..."
sfc /scannow

# ----------------------------
# 3. App Removal
# ----------------------------
Write-Host "`n[STEP 3/8] Removing unnecessary apps..."

$removeAppsPath = Join-Path $scriptDir "scripts\bloatware\remove-apps.ps1"
if (Test-Path $removeAppsPath) { powershell.exe -ExecutionPolicy Bypass -File "$removeAppsPath" }

$removeEdgePath = Join-Path $scriptDir "scripts\bloatware\remove-edge.ps1"
if (Test-Path $removeEdgePath) { powershell.exe -ExecutionPolicy Bypass -File "$removeEdgePath" }

$gamebarAnnoyancePath = Join-Path $scriptDir "scripts\bloatware\remove-gamebar-annoyance.bat"
if (Test-Path $gamebarAnnoyancePath) {
    & cmd.exe /c "$gamebarAnnoyancePath"
}

$removeOneDrivePath = Join-Path $scriptDir "scripts\bloatware\remove-onedrive.ps1"
if (Test-Path $removeOneDrivePath) { powershell.exe -ExecutionPolicy Bypass -File "$removeOneDrivePath" }

# ----------------------------
# 4. Network Optimizations
# ----------------------------
Write-Host "`n[STEP 4/8] Optimizing network settings..."
Write-Host "Resetting TCP/IP settings..."

ipconfig /flushdns
ipconfig /release
ipconfig /renew

$interfaceName = "Ethernet"  # Change if your interface has a different name

netsh interface ip set dns name="$interfaceName" static 8.8.8.8
netsh interface ip add dns name="$interfaceName" 8.8.4.4 index=2
netsh int tcp set global rss=disabled
netsh int tcp set global autotuninglevel=restricted

# ----------------------------
# 5. Disabling Features
# ----------------------------
Write-Host "`n[STEP 5/8] Disabling Windows features..."

Write-Host "Disabling Internet Explorer..."
dism /online /Remove-Capability /CapabilityName:Browser.InternetExplorer~~~~0.0.11.0 /NoRestart

Write-Host "Disabling Hyper-V..."
dism /online /Disable-Feature /FeatureName:Microsoft-Hyper-V-All /NoRestart

Write-Host "Disabling Windows Media Player..."
dism /online /Disable-Feature /FeatureName:WindowsMediaPlayer /NoRestart

Write-Host "Disabling Recall..."
dism /online /Disable-Feature /FeatureName:Recall /NoRestart

# ----------------------------
# 6. System Settings
# ----------------------------
Write-Host "`n[STEP 6/8] Applying system optimizations..."

$registryPath = Join-Path $scriptDir "scripts\main\registry.ps1"
if (Test-Path $registryPath) { powershell.exe -ExecutionPolicy Bypass -File "$registryPath" }

$servicesPath = Join-Path $scriptDir "scripts\main\services.ps1"
if (Test-Path $servicesPath) { powershell.exe -ExecutionPolicy Bypass -File "$servicesPath" }

$telemetryPath = Join-Path $scriptDir "scripts\main\telemetry.ps1"
if (Test-Path $telemetryPath) { powershell.exe -ExecutionPolicy Bypass -File "$telemetryPath" }

# ----------------------------
# 7. Power Settings
# ----------------------------
Write-Host "`n[STEP 7/8] Configuring power plan..."
Write-Host "Activating Ultimate Performance mode..."

try {
    $scheme = powercfg -list | Select-String 'Ultimate Performance'
    if (-not $scheme) {
        powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 | Out-Null
    }
    $schemeGuid = (powercfg -list | Select-String 'Ultimate Performance').ToString() -replace '.*\s(\{.*\})','${1}'
    powercfg -setactive $schemeGuid
} catch {
    Write-Warning "Failed to activate Ultimate Performance power plan."
}

Write-Host "Disabling hibernation..."
powercfg /hibernate off

# ----------------------------
# 8. Finalization
# ----------------------------
Write-Host "`n[STEP 8/8] Finalizing optimizations..."

Write-Host "Checking system integrity..."
sfc /scannow

Write-Host "Optimizing storage..."
defrag C: /O /U

Write-Host "Restarting critical services..."
Try {
    net stop "Windows Audio" -ErrorAction SilentlyContinue | Out-Null
    net start "Windows Audio" -ErrorAction SilentlyContinue | Out-Null
} catch {
    Write-Warning "Failed to restart Windows Audio service."
}


# ----------------------------
# Conclusion
# ----------------------------
Write-Host ""
Write-Host "=============================================="
Write-Host "      OPTIMIZATION COMPLETED SUCCESSFULLY!    "
Write-Host "==============================================`n"

Write-Host "Recommendations:"
Write-Host "1. Restart your computer."
Write-Host "2. Check if all drivers are updated."
Write-Host "3. Configure your essential programs.`n"

Write-Host "Notes:"
Write-Host "- Some changes require a restart."
Write-Host "- Removed features will no longer be available.`n"

Pause

# Restart Explorer to apply changes
Write-Host "Restarting Explorer..."
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Start-Process explorer.exe

exit 0
