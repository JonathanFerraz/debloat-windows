#Requires -RunAsAdministrator

Clear-Host
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host "        RESTORE SCRIPT FOR SERVICES           " -ForegroundColor Yellow
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host ""

# --- Initial Setup and Admin Check ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script must be run as Administrator."
    Start-Sleep -Seconds 10
    exit
}

# --- Select Backup to Restore ---
$backupBaseDir = "C:\Ryzen Optimizer\Backup"
if (-not (Test-Path $backupBaseDir)) {
    Write-Error "Backup directory not found: $backupBaseDir"
    Start-Sleep -Seconds 10
    exit
}

$backups = Get-ChildItem -Path $backupBaseDir -Directory -Filter "services-*" | Sort-Object CreationTime -Descending
if ($backups.Count -eq 0) {
    Write-Error "No backups found in $backupBaseDir"
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
$backupFile = Join-Path $selectedBackupDir "services-backup.csv"

Write-Host "You have selected to restore from: $selectedBackupDir" -ForegroundColor Green
Read-Host "Press Enter to begin the restoration process..."

# --- Restoration Process ---
if (!(Test-Path $backupFile)) {
    Write-Error "Backup file 'services-backup.csv' not found in the selected directory. Aborting."
    Start-Sleep -Seconds 10
    exit
}

$services = Import-Csv -Path $backupFile

foreach ($svc in $services) {
    try {
        # First, set the startup type
        Set-Service -Name $svc.Name -StartupType $svc.StartType -ErrorAction Stop
        
        # Then, adjust the running state
        if ($svc.Status -eq "Running") {
            Start-Service -Name $svc.Name -ErrorAction SilentlyContinue
        }
        # Note: No need for an explicit Stop-Service. 
        # If the original state was Stopped, changing the StartupType is enough.
        # The service will be started on the next reboot or manual start if needed.
        
        Write-Host "Service '$($svc.Name)' startup type restored to '$($svc.StartType)'."
    } catch {
        Write-Warning "Error restoring '$($svc.Name)': $($_.Exception.Message)"
    }
}

Write-Host ""
Write-Host "Service restoration process is complete." -ForegroundColor Green
Write-Host "A system reboot is recommended for all changes to take full effect."