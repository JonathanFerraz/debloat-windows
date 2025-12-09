#Requires -RunAsAdministrator

# ----------------------------
# Initial Setup
# ----------------------------
Clear-Host
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host "     RESTORE SCRIPT FOR RYZEN OPTIMIZER       " -ForegroundColor Yellow
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host ""

# Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script must be run as Administrator."
    Start-Sleep -Seconds 10
    exit
}

# ----------------------------
# Select Backup to Restore
# ----------------------------
$backupBaseDir = "C:\Ryzen Optimizer\Backup"
if (-not (Test-Path $backupBaseDir)) {
    Write-Error "Backup directory not found: $backupBaseDir"
    Start-Sleep -Seconds 10
    exit
}

$backups = Get-ChildItem -Path $backupBaseDir -Directory -Filter "telemetry-*" | Sort-Object CreationTime -Descending
if ($backups.Count -eq 0) {
    Write-Error "No backups found in $backupBaseDir"
    Start-Sleep -Seconds 10
    exit
}

Write-Host "Please select a backup to restore:"
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
Write-Host "You have selected to restore from: $selectedBackupDir" -ForegroundColor Cyan
Read-Host "Press Enter to begin the restoration process..."

#================================================================================
# SCRIPT BODY - RESTORATION
#================================================================================

# --- 1. Restore Hosts File ---
Write-Host "--- Restoring Hosts file..." -ForegroundColor Green
$hostsBackupFile = Join-Path $selectedBackupDir "hosts.backup"
if (Test-Path $hostsBackupFile) {
    Copy-Item -Path $hostsBackupFile -Destination "$env:windir\System32\drivers\etc\hosts" -Force
    Write-Host "Hosts file successfully restored."
} else {
    Write-Warning "Hosts backup file not found. Skipping."
}

# --- 2. Restore Services ---
Write-Host "--- Restoring Services states..." -ForegroundColor Green
$serviceBackupFile = Join-Path $selectedBackupDir "telemetry-services-backup.csv"
if (Test-Path $serviceBackupFile) {
    $servicesToRestore = Import-Csv -Path $serviceBackupFile
    foreach ($serviceInfo in $servicesToRestore) {
        try {
            Write-Host "Restoring service $($serviceInfo.Name) to StartupType: $($serviceInfo.StartupType)"
            Set-Service -Name $serviceInfo.Name -StartupType $serviceInfo.StartupType -ErrorAction Stop
            if ($serviceInfo.Status -eq 'Running') {
                Start-Service -Name $serviceInfo.Name -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Error "Failed to restore service $($serviceInfo.Name). Error: $($_.Exception.Message)"
        }
    }
} else {
    Write-Warning "Services backup file not found. Skipping."
}

# --- 3. Restore Scheduled Tasks ---
Write-Host "--- Restoring Scheduled Tasks states..." -ForegroundColor Green
$taskBackupFile = Join-Path $selectedBackupDir "telemetry-tasks-backup.csv"
if (Test-Path $taskBackupFile) {
    $tasksToRestore = Import-Csv -Path $taskBackupFile
    foreach ($taskInfo in $tasksToRestore) {
        if ($taskInfo.State -ne 'Disabled') {
             try {
                Write-Host "Enabling task: $($taskInfo.Path)"
                Get-ScheduledTask -TaskPath $taskInfo.Path | Enable-ScheduledTask -ErrorAction Stop
            }
            catch {
                 Write-Error "Failed to enable task $($taskInfo.Path). Error: $($_.Exception.Message)"
            }
        }
    }
} else {
    Write-Warning "Tasks backup file not found. Skipping."
}


# --- 4. Restore Environment Variable ---
Write-Host "--- Restoring Environment Variables..." -ForegroundColor Green
$envVarBackupFile = Join-Path $selectedBackupDir "telemetry-env-vars-backup.csv"
if (Test-Path $envVarBackupFile) {
    $envVarsToRestore = Import-Csv -Path $envVarBackupFile
    foreach ($envVarInfo in $envVarsToRestore) {
        if ($envVarInfo.ExistedBefore -eq 'True') {
            [Environment]::SetEnvironmentVariable($envVarInfo.Name, $envVarInfo.Value, 'Machine')
            Write-Host "Restored environment variable '$($envVarInfo.Name)'."
        } else {
            # If it didn't exist, we remove it by setting its value to null
            [Environment]::SetEnvironmentVariable($envVarInfo.Name, $null, 'Machine')
            Write-Host "Removed environment variable '$($envVarInfo.Name)' as it did not exist before."
        }
    }
} else {
    Write-Warning "Environment variable backup file not found. Skipping."
}


# --- 5. Restore Registry ---
Write-Host "--- Restoring all Registry values..." -ForegroundColor Green
$regBackupFile = Join-Path $selectedBackupDir "telemetry-registry-backup.csv"
if (Test-Path $regBackupFile) {
    $regToRestore = Import-Csv -Path $regBackupFile
    $totalKeys = $regToRestore.Count
    $processedKeys = 0
    foreach ($regInfo in $regToRestore) {
        $processedKeys++
        Write-Progress -Activity "Restoring Registry" -Status "Processing key $processedKeys of $totalKeys" -PercentComplete (($processedKeys / $totalKeys) * 100)
        try {
            if ($regInfo.ExistedBefore -eq 'True') {
                # The value existed, so we set it back to what it was
                if (-not (Test-Path $regInfo.Path)) {
                    New-Item -Path $regInfo.Path -Force | Out-Null
                }
                # For MultiString, value from CSV needs to be handled as an array
                $valueToSet = if ($regInfo.Type -eq 'MultiString') { @($regInfo.Value) } else { $regInfo.Value }
                
                Set-ItemProperty -Path $regInfo.Path -Name $regInfo.Name -Value $valueToSet -Type $regInfo.Type -Force -ErrorAction Stop
            } else {
                # The value did not exist before, so we remove it
                if (Get-ItemProperty -Path $regInfo.Path -Name $regInfo.Name -ErrorAction SilentlyContinue) {
                    Remove-ItemProperty -Path $regInfo.Path -Name $regInfo.Name -Force -ErrorAction Stop
                }
            }
        }
        catch {
            Write-Error "Failed to restore registry value '$($regInfo.Name)' at '$($regInfo.Path)'. Error: $($_.Exception.Message)"
        }
    }
} else {
    Write-Warning "Registry backup file not found. Skipping."
}


#================================================================================
# SCRIPT COMPLETION
#================================================================================
Write-Host ""
Write-Host "==============================================" -ForegroundColor Green
Write-Host "           RESTORE PROCESS COMPLETE           " -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green
Write-Host "All backed up settings have been restored."
Write-Host "It is HIGHLY RECOMMENDED to reboot your system for all changes to take full effect." -ForegroundColor Yellow