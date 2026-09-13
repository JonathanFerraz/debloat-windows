#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
Import-Module "$PSScriptRoot\..\lib\RyzenOptimizer.psm1" -ErrorAction Stop
$backupDir = Join-Path "$env:SystemDrive\Ryzen Optimizer\Backup" ("services-" + (Get-Date -Format 'yyyy-MM-dd_HH-mm-ss-fff'))
New-Item -ItemType Directory -Path $backupDir -ErrorAction Stop | Out-Null
# Capture all installed services once, including per-user instances and driver helpers.
$backupData = @(Get-ServiceBackup)
if (-not $backupData.Count) { throw 'No service states were captured.' }
$backupData | Export-Csv -LiteralPath (Join-Path $backupDir 'services-backup.csv') -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
Write-Host "Service backup: $backupDir"
