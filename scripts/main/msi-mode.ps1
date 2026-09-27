# ==============================================
# R Y Z E N Optimizer
# MSI (Message Signaled Interrupts) Mode
# ==============================================
# Switches GPU/NIC interrupt delivery from legacy line-based IRQ sharing to
# per-device MSI vectors, cutting DPC/interrupt latency. Reboot required.

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$SkipBackup,
    [switch]$Disable,
    [string[]]$DeviceClass = @('Display', 'Net')
)

$Host.UI.RawUI.WindowTitle = "Ryzen Optimizer - MSI Mode"
Import-Module "$PSScriptRoot\..\lib\RyzenOptimizer.psm1" -ErrorAction Stop

Write-Step "MSI (Message Signaled Interrupts) Mode" -Level Header

$value = if ($Disable) { 0 } else { 1 }
$action = if ($Disable) { 'Disabling' } else { 'Enabling' }

foreach ($class in $DeviceClass) {
    $devices = @(Get-PnpDevice -Class $class -PresentOnly -ErrorAction SilentlyContinue | Where-Object Status -eq 'OK')
    if (-not $devices.Count) {
        Write-Step "No present '$class' devices found." -Level Warning
        continue
    }

    foreach ($device in $devices) {
        $keyPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($device.InstanceId)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
        if (Set-RegistryValue -Path $keyPath -Name 'MSISupported' -Type 'REG_DWORD' -Value $value -Force) {
            Write-Step "$action MSI mode: $($device.FriendlyName)" -Level Success
        } else {
            Write-Step "Failed on: $($device.FriendlyName)" -Level Warning
        }
    }
}

Write-Step "Reboot required for MSI mode changes to take effect." -Level Warning
Write-Step "Revert with: msi-mode.ps1 -Disable" -Level Info
