#Requires -RunAsAdministrator

Clear-Host
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host "      BACKUP SCRIPT FOR SYSTEM DEVICES        " -ForegroundColor Yellow
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host ""

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script must be run as Administrator."
    Start-Sleep -Seconds 10
    exit
}

if (-not (Get-Command Get-PnpDevice -ErrorAction SilentlyContinue)) {
    Write-Error "Get-PnpDevice is not available on this system."
    Start-Sleep -Seconds 10
    exit
}

$backupBaseDir = "C:\Ryzen Optimizer\Backup"
$timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$folderName = "devices-$timestamp"
$backupDir = Join-Path -Path $backupBaseDir -ChildPath $folderName
New-Item -Path $backupDir -ItemType Directory -Force | Out-Null

$backupFile = Join-Path $backupDir "devices-backup.csv"
Write-Host "Generating backup..."
Write-Host "Backup will be saved to: $backupFile" -ForegroundColor Cyan

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
$backupData = @()

foreach ($friendlyName in $TargetSystemDevices) {
    $matches = $systemDevices | Where-Object { $_.FriendlyName -eq $friendlyName }

    if (-not $matches) {
        $backupData += [PSCustomObject]@{
            FriendlyName = $friendlyName
            InstanceId   = ""
            Class        = "System"
            Status       = "NotFound"
            Problem      = ""
            Manufacturer = ""
            Present      = ""
        }
        continue
    }

    foreach ($device in $matches) {
        $backupData += [PSCustomObject]@{
            FriendlyName = $device.FriendlyName
            InstanceId   = $device.InstanceId
            Class        = $device.Class
            Status       = $device.Status
            Problem      = $device.Problem
            Manufacturer = $device.Manufacturer
            Present      = $device.Present
        }
    }
}

$backupData | Export-Csv -Path $backupFile -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Backup process complete!" -ForegroundColor Green
Write-Host "$($backupData.Count) device record(s) were backed up successfully."
