# ==============================================
# R Y Z Ξ N Optimizer
# Disable Xbox Login Features (Post-Debloat)
# Version: 1.0 | Date: 2026-02-14
# ==============================================

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$RemoveXboxApps
)

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[ERROR] Run this script as Administrator." -ForegroundColor Red
    exit 1
}

$Host.UI.RawUI.WindowTitle = "Ryzen Optimizer - Disable Xbox Login Features"
Clear-Host

Write-Host "==============================================" -ForegroundColor Yellow
Write-Host "   DISABLE XBOX LOGIN FEATURES (POST-DEBLOAT) " -ForegroundColor Yellow
Write-Host "==============================================" -ForegroundColor Yellow

# 1) Hosts: block Microsoft login endpoint used by Xbox sign-in flow
$hostsPath = "$env:windir\System32\drivers\etc\hosts"
$hostsBackup = "$hostsPath.xboxdisable.bak"

try {
    if (Test-Path $hostsPath) {
        Copy-Item -Path $hostsPath -Destination $hostsBackup -Force

        $lineToAdd = "0.0.0.0 login.live.com"
        $existing = Get-Content -Path $hostsPath -ErrorAction SilentlyContinue

        if (-not ($existing | Where-Object { $_ -match '^\s*0\.0\.0\.0\s+login\.live\.com\s*$' })) {
            Add-Content -Path $hostsPath -Value $lineToAdd
            Write-Host "[OK] Added hosts block for login.live.com" -ForegroundColor Green
        }
        else {
            Write-Host "[OK] hosts already blocks login.live.com" -ForegroundColor Green
        }
    }
}
catch {
    Write-Warning "Failed to update hosts file: $($_.Exception.Message)"
}

# 2) Registry: deny app access to account info (affects Xbox sign-in)
try {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAccountInfo" -Type DWord -Value 2 -Force

    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name "Value" -Type String -Value "Deny" -Force

    Write-Host "[OK] Account info privacy policy set to deny." -ForegroundColor Green
}
catch {
    Write-Warning "Failed to configure registry policy: $($_.Exception.Message)"
}

# 3) Services: disable Xbox login stack
$xboxServices = @(
    'XblAuthManager',
    'XblGameSave',
    'XboxNetApiSvc',
    'GamingServices',
    'GamingServicesNet'
)

foreach ($svcName in $xboxServices) {
    try {
        $svc = Get-Service -Name $svcName -ErrorAction Stop

        if ($svc.Status -eq 'Running') {
            Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
        }

        Set-Service -Name $svcName -StartupType Disabled -ErrorAction Stop
        Write-Host "[OK] $svcName => Disabled" -ForegroundColor Green
    }
    catch {
        Write-Host "[INFO] Service not found: $svcName" -ForegroundColor Yellow
    }
}

# 4) Optional: remove Xbox-related app packages
if ($RemoveXboxApps) {
    Write-Host "Removing Xbox packages..." -ForegroundColor Yellow

    $xboxPackages = @(
        'Microsoft.XboxGameBar',
        'Microsoft.Xbox.TCUI',
        'Microsoft.XboxGamingOverlay',
        'Microsoft.XboxIdentityProvider',
        'Microsoft.XboxSpeechToTextOverlay',
        'Microsoft.GamingApp'
    )

    foreach ($pkg in $xboxPackages) {
        try {
            $installed = Get-AppxPackage -AllUsers | Where-Object { $_.Name -eq $pkg }
            if ($installed) {
                $installed | ForEach-Object {
                    Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction SilentlyContinue
                }
            }

            $provisioned = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $pkg }
            if ($provisioned) {
                $provisioned | ForEach-Object {
                    Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction SilentlyContinue
                }
            }

            Write-Host "[OK] Processed package: $pkg" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed package operation for ${pkg}: $($_.Exception.Message)"
        }
    }
}

Write-Host ""
Write-Host "Done. Xbox login features were disabled." -ForegroundColor Yellow
Write-Host "To revert, run: scripts\fixes\repair-xbox-login.ps1" -ForegroundColor Cyan
