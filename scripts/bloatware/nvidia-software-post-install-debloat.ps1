# ==============================================
# R Y Z Ξ N Optimizer
# NVIDIA Software Post-Install Debloat
# Version: 1.0 | Date: 2026-02-14
# ==============================================

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$EnableTrace,
    [switch]$Aggressive,
    [switch]$RemoveGeForceExperience,
    [switch]$AutoReboot,
    [ValidateSet('Preserve','Driver','Debloat')][string]$GpuServiceProfile = 'Preserve'
)

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[ERROR] Run this script as Administrator." -ForegroundColor Red
    exit 1
}

if ($EnableTrace) {
    Set-PSDebug -Trace 1
}

$Host.UI.RawUI.WindowTitle = "Ryzen Optimizer - NVIDIA Debloat"
Clear-Host

Write-Host "==============================================" -ForegroundColor Green
Write-Host "   NVIDIA SOFTWARE POST-INSTALL DEBLOAT       " -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green

Import-Module "$PSScriptRoot\..\lib\RyzenOptimizer.psm1" -ErrorAction Stop

Write-Host "Applying safe NVIDIA debloat profile..." -ForegroundColor Cyan

# 1) Disable telemetry/update services (safe profile)
Set-ServiceSafe -Name 'NvTelemetryContainer' -StartupType Disabled -StopIfRunning
Set-ServiceSafe -Name 'NvTelemetryNetworkService' -StartupType Disabled -StopIfRunning
Set-ServiceSafe -Name 'NVDisplay.ContainerLocalSystem' -StartupType Automatic
Set-NvidiaContainerProfile -Profile $GpuServiceProfile

# 2) Disable NVIDIA telemetry/update tasks
Disable-TasksByRegex -Regex 'NvTmMon|NvTmRep|NvProfileUpdater|NvDriverUpdateCheck|NvNodeLauncher|NvContainerTelemetry'

# 3) Aggressive mode (optional)
if ($Aggressive) {
    Write-Host "Applying aggressive NVIDIA debloat profile..." -ForegroundColor Yellow

    Set-NvidiaContainerProfile -Profile Aggressive

    Disable-TasksByRegex -Regex 'NVIDIA|NvContainer|GeForce'

    try {
        Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'NvBackend' -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'NvContainer' -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'NVIDIA GeForce Experience' -ErrorAction SilentlyContinue
        Write-Host "[OK] NVIDIA startup entries cleaned (where present)." -ForegroundColor Green
    }
    catch {
        Write-Host "[INFO] Startup entries cleanup finished with minor warnings." -ForegroundColor Yellow
    }
}

# 4) Optional: uninstall GeForce Experience
if ($RemoveGeForceExperience) {
    Write-Host "Removing NVIDIA GeForce Experience (optional)..." -ForegroundColor Yellow

    try {
        $uninstallRoots = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )

        $gfe = Get-ItemProperty $uninstallRoots -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match 'GeForce Experience' } |
            Select-Object -First 1

        if ($gfe -and $gfe.UninstallString) {
            $cmd = $gfe.UninstallString
            if ($cmd -match '^"([^"]+)"\s*(.*)$') {
                $exe = $matches[1]
                $uninstallArgs = $matches[2]
                Start-Process -FilePath $exe -ArgumentList "$uninstallArgs /quiet" -Wait -ErrorAction SilentlyContinue
            }
            else {
                Start-Process -FilePath 'cmd.exe' -ArgumentList "/c $cmd /quiet" -Wait -ErrorAction SilentlyContinue
            }
            Write-Host "[OK] GeForce Experience uninstall command executed." -ForegroundColor Green
        }
        else {
            Write-Host "[INFO] GeForce Experience not found." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Warning "Failed to run GeForce Experience uninstall: $($_.Exception.Message)"
    }
}

if ($EnableTrace) {
    Set-PSDebug -Trace 0
}

Write-Host ""
Write-Host "NVIDIA debloat completed." -ForegroundColor Green
Write-Host "A reboot is recommended." -ForegroundColor Cyan

if ($AutoReboot) {
    Restart-Computer
}
