# ==============================================
# R Y Z Ξ N Optimizer
# Xbox Login Repair (Post-Debloat)
# Version: 1.0 | Date: 2026-02-13
# ==============================================

#Requires -RunAsAdministrator

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[ERROR] Run this script as Administrator." -ForegroundColor Red
    exit 1
}

$Host.UI.RawUI.WindowTitle = "Ryzen Optimizer - Xbox Login Repair"
Clear-Host

Write-Host "==============================================" -ForegroundColor Green
Write-Host "        XBOX LOGIN REPAIR (POST-DEBLOAT)      " -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green

# 1) Hosts cleanup (remove auth-related blocks)
$hostsPath = "$env:windir\System32\drivers\etc\hosts"
$hostsBackup = "$hostsPath.xboxrepair.bak"

try {
    if (Test-Path $hostsPath) {
        Copy-Item -Path $hostsPath -Destination $hostsBackup -Force

        $authPatterns = @(
            'login.live.com',
            'xboxlive.com',
            'xsts.auth.xboxlive.com',
            'user.auth.xboxlive.com',
            'device.auth.xboxlive.com',
            'title.auth.xboxlive.com',
            'accounts.xboxlive.com'
        )

        $content = Get-Content -Path $hostsPath -ErrorAction Stop
        $filtered = $content | Where-Object {
            $line = $_.Trim().ToLowerInvariant()
            if ($line -eq '' -or $line.StartsWith('#')) { return $true }

            foreach ($pattern in $authPatterns) {
                if ($line -match [regex]::Escape($pattern)) {
                    return $false
                }
            }

            return $true
        }

        Set-Content -Path $hostsPath -Value $filtered -Encoding ASCII -Force
        Write-Host "[OK] Hosts cleaned. Backup: $hostsBackup" -ForegroundColor Green
    }
}
catch {
    Write-Warning "Failed to clean hosts file: $($_.Exception.Message)"
}

# 2) Registry compatibility fixes
try {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAccountInfo" -Type DWord -Value 1 -Force

    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name "Value" -Type String -Value "Allow" -Force

    Write-Host "[OK] Account info privacy policy adjusted for Xbox sign-in." -ForegroundColor Green
}
catch {
    Write-Warning "Failed to adjust registry privacy settings: $($_.Exception.Message)"
}

# 3) Ensure critical services for Xbox/Microsoft auth
$servicePlan = @(
    @{ Name = 'AppXSVC'; StartupType = 'Manual'; StartNow = $false },
    @{ Name = 'ClipSVC'; StartupType = 'Manual'; StartNow = $true },
    @{ Name = 'wlidsvc'; StartupType = 'Manual'; StartNow = $true },
    @{ Name = 'TokenBroker'; StartupType = 'Manual'; StartNow = $false },
    @{ Name = 'InstallService'; StartupType = 'Manual'; StartNow = $false },
    @{ Name = 'XblAuthManager'; StartupType = 'Manual'; StartNow = $true },
    @{ Name = 'XblGameSave'; StartupType = 'Manual'; StartNow = $true },
    @{ Name = 'XboxNetApiSvc'; StartupType = 'Manual'; StartNow = $true },
    @{ Name = 'GamingServices'; StartupType = 'Automatic'; StartNow = $true },
    @{ Name = 'GamingServicesNet'; StartupType = 'Manual'; StartNow = $true }
)

foreach ($svc in $servicePlan) {
    try {
        $service = Get-Service -Name $svc.Name -ErrorAction Stop
        Set-Service -Name $svc.Name -StartupType $svc.StartupType -ErrorAction Stop

        if ($svc.StartNow -and $service.Status -ne 'Running') {
            Start-Service -Name $svc.Name -ErrorAction SilentlyContinue
        }

        Write-Host "[OK] $($svc.Name) => $($svc.StartupType)" -ForegroundColor Green
    }
    catch {
        Write-Host "[INFO] Service not found: $($svc.Name)" -ForegroundColor Yellow
    }
}

# 4) Refresh Store infrastructure and DNS
try {
    ipconfig /flushdns | Out-Null
    Start-Process -FilePath "wsreset.exe" -WindowStyle Hidden
    Write-Host "[OK] DNS cache flushed and Store reset requested." -ForegroundColor Green
}
catch {
    Write-Warning "Store reset step failed: $($_.Exception.Message)"
}

Write-Host ""
Write-Host "NEXT STEPS:" -ForegroundColor Cyan
Write-Host "1) Reboot the PC."
Write-Host "2) Open Microsoft Store and install/repair:"
Write-Host "   - Gaming Services"
Write-Host "   - Xbox Identity Provider"
Write-Host "   - Xbox App"
Write-Host "3) Try Xbox login again."
Write-Host ""
Write-Host "Done." -ForegroundColor Green
