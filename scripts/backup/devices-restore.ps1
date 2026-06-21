#Requires -RunAsAdministrator

Clear-Host
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host "      RESTORE SCRIPT FOR SYSTEM DEVICES       " -ForegroundColor Yellow
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host ""

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script must be run as Administrator."
    Start-Sleep -Seconds 10
    exit
}

if (-not (Get-Command Enable-PnpDevice -ErrorAction SilentlyContinue)) {
    Write-Error "Enable-PnpDevice is not available on this system."
    Start-Sleep -Seconds 10
    exit
}

$backupBaseDir = "C:\Ryzen Optimizer\Backup"
if (-not (Test-Path $backupBaseDir)) {
    Write-Error "Backup directory not found: $backupBaseDir"
    Start-Sleep -Seconds 10
    exit
}

$backups = Get-ChildItem -Path $backupBaseDir -Directory -Filter "devices-*" | Sort-Object CreationTime -Descending
if ($backups.Count -eq 0) {
    Write-Error "No device backups found in $backupBaseDir"
    Start-Sleep -Seconds 10
    exit
}

Write-Host "Please select a backup to restore:" -ForegroundColor Cyan
for ($i = 0; $i -lt $backups.Count; $i++) {
    Write-Host "[$i] $($backups[$i].Name)"
}

$choice = Read-Host "Enter the number of the backup you wish to restore"
if ($choice -notmatch '^\d+$' -or [int]$choice -lt 0 -or [int]$choice -ge $backups.Count) {
    Write-Error "Invalid selection. Exiting."
    Start-Sleep -Seconds 10
    exit
}

$selectedBackupDir = $backups[[int]$choice].FullName
$backupFile = Join-Path $selectedBackupDir "devices-backup.csv"

Write-Host "You have selected to restore from: $selectedBackupDir" -ForegroundColor Green
Read-Host "Press Enter to begin the restoration process..."

if (-not (Test-Path $backupFile)) {
    Write-Error "Backup file 'devices-backup.csv' not found in the selected directory. Aborting."
    Start-Sleep -Seconds 10
    exit
}

$devices = Import-Csv -Path $backupFile
$restoredCount = 0
$skippedCount = 0
$failedCount = 0

foreach ($device in $devices) {
    if ([string]::IsNullOrWhiteSpace($device.InstanceId) -or $device.Status -eq "NotFound") {
        Write-Host "Skipping '$($device.FriendlyName)' (not found in original backup)." -ForegroundColor DarkGray
        $skippedCount++
        continue
    }

    if ($device.Status -ne "OK") {
        Write-Host "Skipping '$($device.FriendlyName)' (original status was '$($device.Status)')." -ForegroundColor DarkGray
        $skippedCount++
        continue
    }

    try {
        Enable-PnpDevice -InstanceId $device.InstanceId -Confirm:$false -ErrorAction Stop | Out-Null
        Write-Host "Enabled '$($device.FriendlyName)'." -ForegroundColor Green
        $restoredCount++
    }
    catch {
        Write-Warning "Error restoring '$($device.FriendlyName)': $($_.Exception.Message)"
        $failedCount++
    }
}

Write-Host ""
Write-Host "System device restoration process is complete." -ForegroundColor Green
Write-Host "  Enabled: $restoredCount" -ForegroundColor Green
Write-Host "  Skipped: $skippedCount" -ForegroundColor DarkYellow
Write-Host "  Failed:  $failedCount" -ForegroundColor Red
Write-Host "A system reboot is recommended for all changes to take full effect."
