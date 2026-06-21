# ==============================================
# Ryzen Optimizer
# Disable selected System Devices
# ==============================================

#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$SkipBackup
)

$Host.UI.RawUI.WindowTitle = "Ryzen Optimizer - System Devices"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] Run this script as Administrator." -ForegroundColor Red
    exit 1
}

if (-not (Get-Command Get-PnpDevice -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Get-PnpDevice is not available on this system." -ForegroundColor Red
    exit 1
}

if (-not $SkipBackup) {
    $backupPath = Join-Path $PSScriptRoot "..\backup\devices-backup.ps1"
    if (Test-Path $backupPath) { & $backupPath }
}

Write-Host ""
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host "     DISABLE SELECTED SYSTEM DEVICES          " -ForegroundColor Yellow
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host ""

$TargetSystemDevices = @(
    "AMD Controller Emulation",
    "AMD Crash Defender",
    "Composite Bus Enumerator",
    "High Precision Event Timer",
    "Microsoft Hyper-V Virtualization Infrastructure Driver",
    "Microsoft Virtual Drive Enumerator",
    "NDIS Virtual Network Adapter Enumerator",
    "Remote Desktop Device Redirector Bus",
    "System Speaker"
)

$systemDevices = Get-PnpDevice -Class System -ErrorAction SilentlyContinue
$disabledCount = 0
$skippedCount = 0
$failedCount = 0

foreach ($friendlyName in $TargetSystemDevices) {
    $matches = $systemDevices | Where-Object { $_.FriendlyName -eq $friendlyName }

    if (-not $matches) {
        Write-Host "Skipping '$friendlyName' (device not found)." -ForegroundColor DarkYellow
        $skippedCount++
        continue
    }

    foreach ($device in $matches) {
        $label = "$($device.FriendlyName) [$($device.InstanceId)]"

        if ($device.Problem -eq "CM_PROB_DISABLED") {
            Write-Host "Skipping '$label' (already disabled)." -ForegroundColor DarkGray
            $skippedCount++
            continue
        }

        try {
            if ($PSCmdlet.ShouldProcess($label, "Disable-PnpDevice")) {
                Disable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false -ErrorAction Stop | Out-Null
                Write-Host "Disabled '$label'." -ForegroundColor Green
                $disabledCount++
            }
        }
        catch {
            Write-Warning "Failed to disable '$label': $($_.Exception.Message)"
            $failedCount++
        }
    }
}

Write-Host ""
Write-Host "System device configuration completed." -ForegroundColor Yellow
Write-Host "  Disabled: $disabledCount" -ForegroundColor Green
Write-Host "  Skipped:  $skippedCount" -ForegroundColor DarkYellow
Write-Host "  Failed:   $failedCount" -ForegroundColor Red
Write-Host ""
Write-Host "A reboot is recommended for all device changes to take full effect." -ForegroundColor Cyan
