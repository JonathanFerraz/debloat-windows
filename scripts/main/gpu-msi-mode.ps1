# ==============================================
# Ryzen Optimizer
# Enable MSI mode (Message Signaled Interrupts) on the GPU
# Reduces DPC latency / micro-stutter vs legacy line-based IRQs.
# ==============================================

#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Revert  # set MSISupported back to 0 (line-based interrupts)
)

$Host.UI.RawUI.WindowTitle = "Ryzen Optimizer - GPU MSI Mode"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] Run this script as Administrator." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "==============================================" -ForegroundColor Green
Write-Host "        GPU MSI MODE (anti-stutter)           " -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green

$targetValue = if ($Revert) { 0 } else { 1 }
$action = if ($Revert) { "Disabling" } else { "Enabling" }

# Only PCI display adapters that are present and working.
$gpus = Get-PnpDevice -Class Display -Status OK -ErrorAction SilentlyContinue |
    Where-Object { $_.InstanceId -like 'PCI\*' }

if (-not $gpus) {
    Write-Host "No active PCI display adapter found. Skipping." -ForegroundColor DarkYellow
    return
}

$changed = 0
$failed = 0

foreach ($gpu in $gpus) {
    $label = "$($gpu.FriendlyName) [$($gpu.InstanceId)]"
    $msiPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($gpu.InstanceId)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"

    try {
        if (-not (Test-Path $msiPath)) {
            New-Item -Path $msiPath -Force -ErrorAction Stop | Out-Null
        }
        if ($PSCmdlet.ShouldProcess($label, "Set MSISupported=$targetValue")) {
            Set-ItemProperty -Path $msiPath -Name "MSISupported" -Value $targetValue -Type DWord -Force -ErrorAction Stop
            Write-Host "$action MSI mode for $label" -ForegroundColor Green
            $changed++
        }
    }
    catch {
        Write-Warning "Failed on '$label': $($_.Exception.Message)"
        $failed++
    }
}

Write-Host ""
Write-Host "MSI mode update completed. Changed: $changed  Failed: $failed" -ForegroundColor Cyan
Write-Host "A REBOOT is required for interrupt mode changes to take effect." -ForegroundColor Yellow
