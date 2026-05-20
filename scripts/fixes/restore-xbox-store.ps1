# ==============================================
# R Y Z Ξ N Optimizer
# Restore Xbox / Microsoft Store (Revert)
# Version: 1.0 | Date: 2026-04-10
# ==============================================

#Requires -RunAsAdministrator

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[ERROR] Run this script as Administrator." -ForegroundColor Red
    exit 1
}

$Host.UI.RawUI.WindowTitle = "Ryzen Optimizer - Restore Xbox/Store"
Clear-Host

Write-Host "==============================================" -ForegroundColor Green
Write-Host "   RESTORE: Microsoft Store & Xbox packages   " -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green

# If the helper repair script exists, run it (host/registry/services fixes)
$repairScript = Join-Path $PSScriptRoot 'repair-xbox-login.ps1'
if (Test-Path $repairScript) {
    Write-Host "Running existing repair helper: repair-xbox-login.ps1" -ForegroundColor Cyan
    & $repairScript
}
else {
    Write-Host "Helper repair-xbox-login.ps1 not found; applying basic fixes inline." -ForegroundColor Yellow

    # Minimal inline fixes (similar to repair script)
    try {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAccountInfo" -Type DWord -Value 1 -Force
    }
    catch { Write-Warning "Failed to set registry AppPrivacy: $($_.Exception.Message)" }

    $services = @('AppXSVC','ClipSVC','wlidsvc','TokenBroker','InstallService','XblAuthManager','XblGameSave','XboxNetApiSvc','GamingServices','GamingServicesNet')
    foreach ($s in $services) {
        try {
            Set-Service -Name $s -StartupType Manual -ErrorAction Stop
            Start-Service -Name $s -ErrorAction SilentlyContinue
            Write-Host "Service $s set to Manual and started (if available)." -ForegroundColor Green
        }
        catch { Write-Host "Service $s not found or could not be started." -ForegroundColor Yellow }
    }
}

Write-Host ""; Write-Host "Attempting to re-register Microsoft Store and Xbox-related packages..." -ForegroundColor Cyan

# Helper to attempt re-registering packages by name pattern
function Try-RegisterPackagesByPattern {
    param([string]$pattern)
    $pkgs = Get-AppxPackage -AllUsers | Where-Object { $_.Name -like $pattern }
    if ($pkgs) {
        foreach ($p in $pkgs) {
            $manifest = Join-Path $p.InstallLocation 'AppXManifest.xml'
            if (Test-Path $manifest) {
                try {
                    Add-AppxPackage -DisableDevelopmentMode -Register $manifest -ErrorAction Stop
                    Write-Host "Re-registered: $($p.Name)" -ForegroundColor Green
                }
                catch { Write-Warning "Failed re-register for $($p.Name): $($_.Exception.Message)" }
            }
            else { Write-Host "No manifest found for $($p.Name); skipping." -ForegroundColor Yellow }
        }
        return $true
    }
    return $false
}

# Try common patterns
Try-RegisterPackagesByPattern '*WindowsStore*' | Out-Null
Try-RegisterPackagesByPattern '*Store*' | Out-Null
Try-RegisterPackagesByPattern '*Xbox*' | Out-Null
Try-RegisterPackagesByPattern '*GamingServices*' | Out-Null
Try-RegisterPackagesByPattern '*XboxIdentityProvider*' | Out-Null

# If store package wasn't found, try to re-register any remnants in WindowsApps
try {
    $windowsApps = Join-Path $env:ProgramFiles 'WindowsApps'
    if (Test-Path $windowsApps) {
        Get-ChildItem -Path $windowsApps -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'Microsoft\.WindowsStore|Xbox|GamingServices|XboxIdentityProvider' } | ForEach-Object {
            $manifest = Join-Path $_.FullName 'AppxManifest.xml'
            if (Test-Path $manifest) {
                try { Add-AppxPackage -DisableDevelopmentMode -Register $manifest -ErrorAction Stop; Write-Host "Registered from WindowsApps: $($_.Name)" -ForegroundColor Green }
                catch { Write-Warning "Failed to register $($_.Name): $($_.Exception.Message)" }
            }
        }
    }
}
catch { Write-Warning "Error scanning WindowsApps: $($_.Exception.Message)" }

# Attempt DISM/SFC repair if core Store bits are missing (may take long)
Write-Host "If Store registration failed, you can try system repair (DISM + SFC)." -ForegroundColor Cyan
Write-Host "Running quick DISM restorehealth (may take several minutes)..." -ForegroundColor Cyan
try {
    Start-Process -FilePath dism -ArgumentList '/Online','/Cleanup-Image','/RestoreHealth' -Wait -NoNewWindow
    Start-Process -FilePath sfc -ArgumentList '/scannow' -Wait -NoNewWindow
    Write-Host "DISM/SFC completed." -ForegroundColor Green
}
catch { Write-Warning "DISM/SFC run failed to start: $($_.Exception.Message)" }

# Flush DNS and request Store reset
try { ipconfig /flushdns | Out-Null } catch {}
try { Start-Process -FilePath wsreset.exe -WindowStyle Hidden } catch {}

Write-Host ""; Write-Host "Final steps (manual):" -ForegroundColor Cyan
Write-Host "- Reboot the PC." -ForegroundColor Cyan
Write-Host "- Open Microsoft Store and install/repair: Gaming Services, Xbox Identity Provider, Xbox App." -ForegroundColor Cyan
Write-Host "- If install via Store still fails, try opening the Store product page:" -ForegroundColor Cyan
Write-Host "  ms-windows-store://pdp/?ProductId=9MV0B5HZVK9Z" -ForegroundColor Yellow

Write-Host ""; Write-Host "Restore script finished." -ForegroundColor Green
