#Requires -RunAsAdministrator

# ----------------------------
# Initial Setup
# ----------------------------
Clear-Host
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host "        RESTORE SCRIPT FOR REGISTRY TWEAKS      " -ForegroundColor Yellow
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

Write-Host "Searching for registry backups..."
$backups = Get-ChildItem -Path $backupBaseDir -Directory -Filter "registry-*" | Sort-Object CreationTime -Descending

if ($backups.Count -eq 0) {
    Write-Error "No registry backups found in $backupBaseDir"
    Start-Sleep -Seconds 10
    exit
}

Write-Host "Please select a registry backup to restore:"
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

# Define paths to backup files
$regValuesBackupFile = Join-Path $selectedBackupDir "registry-values-backup.csv"
$tasksBackupFile = Join-Path $selectedBackupDir "registry-tasks-backup.csv"
$bcdBackupFile = Join-Path $selectedBackupDir "registry-bcd-backup.bin"
$removedKeysBackupFile = Join-Path $selectedBackupDir "registry-removedkeys-backup.reg"
$networkBackupFile = Join-Path $selectedBackupDir "registry-network-backup.csv"

#================================================================================
# SCRIPT BODY - RESTORATION
#================================================================================

# --- 1. Restore Scheduled Tasks ---
Write-Host "--- Restoring Scheduled Tasks states..." -ForegroundColor Green
if (Test-Path $tasksBackupFile) {
    $tasksToRestore = Import-Csv -Path $tasksBackupFile
    foreach ($taskInfo in $tasksToRestore) {
        try {
            if ($taskInfo.State -eq 'Enabled') {
                Enable-ScheduledTask -TaskName $taskInfo.TaskName
            }
            else {
                Disable-ScheduledTask -TaskName $taskInfo.TaskName
            }
            Write-Host "Task '$($taskInfo.TaskName)' restored to state '$($taskInfo.State)'."
        }
        catch {
            Write-Warning "Failed to restore task $($taskInfo.TaskName)."
        }
    }
}
else {
    Write-Warning "Tasks backup file not found. Skipping."
}


# --- 2. Restore Network (DNS) Settings ---
Write-Host "--- Restoring DNS settings..." -ForegroundColor Green
if (Test-Path $networkBackupFile) {
    $networkToRestore = Import-Csv -Path $networkBackupFile
    foreach ($netInfo in $networkToRestore) {
        try {
            $dnsServers = $netInfo.DNSServers -split ','
            Set-DnsClientServerAddress -InterfaceIndex $netInfo.InterfaceIndex -ServerAddresses ($dnsServers)
            Write-Host "DNS for Interface $($netInfo.InterfaceIndex) restored."
        }
        catch {
            Write-Warning "Failed to restore DNS for Interface $($netInfo.InterfaceIndex)."
        }
    }
}
else {
    Write-Warning "Network backup file not found. Skipping."
}


# --- 3. Restore Removed Registry Keys ---
Write-Host "--- Restoring removed registry keys..." -ForegroundColor Green
if (Test-Path $removedKeysBackupFile) {
    try {
        reg.exe import $removedKeysBackupFile | Out-Null
        Write-Host "Removed keys were successfully restored from .reg file."
    }
    catch {
        Write-Error "Failed to import removed keys from .reg file."
    }
}
else {
    Write-Warning "Backup file for removed keys not found. Skipping."
}

# --- 4. Restore Registry Values ---
Write-Host "--- Restoring all registry values (this may take a moment)..." -ForegroundColor Green
if (Test-Path $regValuesBackupFile) {
    $regToRestore = Import-Csv -Path $regValuesBackupFile
    $totalKeys = $regToRestore.Count
    $processedKeys = 0
    foreach ($regInfo in $regToRestore) {
        $processedKeys++
        Write-Progress -Activity "Restoring Registry Values" -Status "Processing key $processedKeys of $totalKeys" -PercentComplete (($processedKeys / $totalKeys) * 100)
        try {
            if ($regInfo.ExistedBefore -eq 'True') {
                # The value existed, so we set it back to what it was
                if (-not (Test-Path $regInfo.Path)) {
                    New-Item -Path $regInfo.Path -Force | Out-Null
                }
                $valueToSet = if ($regInfo.Type -eq 'MultiString') { @($regInfo.Value) } else { $regInfo.Value }
                Set-ItemProperty -Path $regInfo.Path -Name $regInfo.Name -Value $valueToSet -Type $regInfo.Type -Force -ErrorAction Stop
            }
            else {
                # The value did not exist before, so we remove it
                if (Get-ItemProperty -Path $regInfo.Path -Name $regInfo.Name -ErrorAction SilentlyContinue) {
                    Remove-ItemProperty -Path $regInfo.Path -Name $regInfo.Name -Force -ErrorAction Stop
                }
            }
        }
        catch {
            Write-Error "Failed to restore registry value '$($regInfo.Name)' at '$($regInfo.Path)'."
        }
    }
}
else {
    Write-Warning "Registry values backup file not found. Skipping."
}


# --- 5. Restore BCD ---
Write-Host "--- Restoring Boot Configuration Data (BCD)..." -ForegroundColor Green
if (Test-Path $bcdBackupFile) {
    Write-Host "========================== AVISO IMPORTANTE ==========================" -ForegroundColor Red
    Write-Warning "A restauração do BCD (Configuração de Boot) é uma operação de risco."
    Write-Warning "Se feita incorretamente, pode impedir o sistema de iniciar."
    Write-Warning "O backup atual restaurará TODAS as configurações de boot para o estado em que estavam ANTES de você rodar o script de otimização."
    $confirmation = Read-Host "Você tem certeza ABSOLUTA que deseja restaurar o BCD? (Digite 'S' para confirmar)"
    
    if ($confirmation -eq 'S') {
        try {
            Write-Host "Restaurando BCD... O sistema pode ficar temporariamente sem resposta." -ForegroundColor Yellow
            bcdedit.exe /import $bcdBackupFile /clean | Out-Null
            Write-Host "Restauração do BCD concluída com sucesso." -ForegroundColor Green
        }
        catch {
            Write-Error "FALHA CRÍTICA AO RESTAURAR O BCD. Seu sistema pode não iniciar corretamente."
        }
    }
    else {
        Write-Host "Restauração do BCD cancelada pelo usuário." -ForegroundColor Cyan
    }
}
else {
    Write-Warning "BCD backup file not found. Skipping."
}


#================================================================================
# SCRIPT COMPLETION
#================================================================================
Write-Host ""
Write-Host "==============================================" -ForegroundColor Green
Write-Host "           RESTORE PROCESS COMPLETE           " -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green
Write-Host "All backed up settings have been restored."
Write-Host "É EXTREMAMENTE RECOMENDADO reiniciar o sistema para que TODAS as alterações, especialmente as de boot, tenham efeito." -ForegroundColor Red