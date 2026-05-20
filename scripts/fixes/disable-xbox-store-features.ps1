# ==============================================
# R Y Z Ξ N Optimizer
# Disable Xbox / Microsoft Store compatibility (Revert)
# Version: 1.0 | Date: 2026-04-13
# ==============================================

#Requires -RunAsAdministrator

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[ERROR] Run this script as Administrator." -ForegroundColor Red
    exit 1
}

$Host.UI.RawUI.WindowTitle = "Ryzen Optimizer - Disable Xbox/Store Features"
Clear-Host

Write-Host "==============================================" -ForegroundColor Green
Write-Host "   DISABLE: Microsoft Store & Xbox features   " -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green

Write-Host "Applying minimal Xbox/Store disable profile..." -ForegroundColor Yellow

# 1) Registry: enforce AppPrivacy to deny account info access (policy)
try {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAccountInfo" -Type DWord -Value 2 -Force
    Write-Host "HKLM AppPrivacy\LetAppsAccessAccountInfo = 2" -ForegroundColor Green
}
catch { Write-Warning "Failed to set HKLM AppPrivacy: $($_.Exception.Message)" }

# 2) HKCU ConsentStore: set userAccountInformation to Deny
try {
    $hkcuPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation"
    New-Item -Path $hkcuPath -Force | Out-Null
    Set-ItemProperty -Path $hkcuPath -Name "Value" -Type String -Value "Deny" -Force
    Write-Host "HKCU ConsentStore userAccountInformation => Deny" -ForegroundColor Green
}
catch { Write-Warning "Failed to set HKCU ConsentStore: $($_.Exception.Message)" }

# 3) Hosts: block Xbox/Microsoft auth host if not already present
try {
    $hostsPath = "$env:windir\System32\drivers\etc\hosts"
    $entry = "0.0.0.0 login.live.com"
    $exists = Select-String -Path $hostsPath -Pattern "login\.live\.com" -SimpleMatch -Quiet -ErrorAction SilentlyContinue
    if (-not $exists) {
        Add-Content -Path $hostsPath -Value "`n# Block Xbox login`n$entry"
        Write-Host "Added hosts entry for login.live.com" -ForegroundColor Green
    }
    else { Write-Host "Hosts already contains login.live.com mapping; skipping." -ForegroundColor Yellow }
}
catch { Write-Warning "Failed to update hosts file: $($_.Exception.Message)" }

# 4) Services: stop and disable Xbox-related services
$XboxServicesToDisable = @(
    "XblAuthManager",
    "XblGameSave",
    "XboxNetApiSvc",
    "GamingServices",
    "GamingServicesNet"
)

foreach ($svcName in $XboxServicesToDisable) {
    try {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            if ($svc.Status -eq 'Running') { Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue }
            Set-Service -Name $svcName -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Host "Service $svcName stopped and set to Disabled" -ForegroundColor Green
        }
        else { Write-Host "Service $svcName not found; skipping." -ForegroundColor Yellow }
    }
    catch { Write-Warning "Error handling service ${svcName}: $($_.Exception.Message)" }
}

Write-Host ""; Write-Host "Completed. Reboot recommended for changes to take effect." -ForegroundColor Cyan
Write-Host "If you previously removed Xbox app packages and want to remove them again, run scripts/bloatware/remove-apps.ps1 with -RemoveXboxComponents." -ForegroundColor Cyan
