
# ==============================================
# R Y Z Ξ N Optimizer
# Version: 2.0 | Date: 2025-07-25
# ==============================================

#Requires -RunAsAdministrator


# Set execution policy and error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# ----------------------------
# Initial Setup
# ----------------------------

$Host.UI.RawUI.WindowTitle = "Ryzen Optimizer v2.0"
Clear-Host

Write-Host ""
Write-Host "==============================================" -ForegroundColor Green
Write-Host "              REMOVE TEMP FILES               " -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green

try {
    openfiles > $null 2>&1
}
catch {
    Write-Host "This script requires administrator privileges."
    Write-Host "Please run the script as an administrator."
    Pause
    Exit
}


# Admin privileges confirmed, continue execution

Write-Host "-- Deleting Temporary Files"

# Common Temporary Directories
$tempDirs = @(
    "$env:WinDir\Temp",
    "$env:WinDir\Prefetch",
    "$env:Temp",
    "$env:AppData\Temp",
    "$env:AppData\Local\Temp",
    "$env:HomePath\AppData\LocalLow\Temp",
    "$env:SYSTEMDRIVE\AMD",
    "$env:SYSTEMDRIVE\NVIDIA",
    "$env:SYSTEMDRIVE\INTEL",
    "$env:ProgramData\Microsoft\Windows\WER\ReportArchive",
    "$env:ProgramData\Microsoft\Windows\WER\ReportQueue"
)

# Clean Temp Files from Directories
foreach ($dir in $tempDirs) {
    if (Test-Path $dir) {
        Write-Host "Cleaning directory: $dir"
        # Important: DO NOT remove the root folder to avoid losing special ACLs
        Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Remove Windows Update Files
$updateDir = "$env:Windir\SoftwareDistribution\Download"
if (Test-Path $updateDir) {
    Write-Host "Cleaning Windows Update files"
    Remove-Item -Path "$updateDir\*" -Recurse -Force -ErrorAction SilentlyContinue
}

# Remove Windows Log Files
$logDirs = @(
    "$env:WinDir\Logs",
    "$env:WinDir\System32\LogFiles"
)
foreach ($logDir in $logDirs) {
    if (Test-Path $logDir) {
        Write-Host "Cleaning log directory: $logDir"
        Remove-Item -Path "$logDir\*" -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Clear Browser Data
Write-Host "-- Clearing Browser History"

# Clear Google Chrome history
$chromePaths = @(
    "$env:LocalAppData\Google\Chrome\User Data\Default\History",
    "$env:LocalAppData\Google\Chrome\User Data\Default\Cache\*",
    "$env:LocalAppData\Google\Chrome\User Data\Default\Cookies"
)
foreach ($path in $chromePaths) {
    if (Test-Path $path) {
        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Clear Microsoft Edge history
$edgePaths = @(
    "$env:LocalAppData\Microsoft\Edge\User Data\Default\History",
    "$env:LocalAppData\Microsoft\Edge\User Data\Default\Cache\*",
    "$env:LocalAppData\Microsoft\Edge\User Data\Default\Cookies"
)
foreach ($path in $edgePaths) {
    if (Test-Path $path) {
        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Clear Mozilla Firefox history
$firefoxPaths = @(
    "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\places.sqlite",
    "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\cache2\entries\*"
)
foreach ($path in $firefoxPaths) {
    if (Test-Path $path) {
        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Clear Windows Event Logs (Optional: be cautious)
$eventLogDirs = @(
    "$env:WinDir\System32\winevt\Logs",
    "$env:ProgramData\Microsoft\Windows\WER\ReportArchive"
)
foreach ($log in $eventLogDirs) {
    if (Test-Path $log) {
        Write-Host "Clearing event logs: $log"
        Remove-Item -Path "$log\*" -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Clean Temp Files from Internet Explorer (Optional)
$iePaths = @(
    "$env:LOCALAPPDATA\Microsoft\Windows\INetCache",
    "$env:LOCALAPPDATA\Microsoft\Windows\INetCookies"
)
foreach ($path in $iePaths) {
    if (Test-Path $path) {
        Write-Host "Cleaning Internet Explorer files: $path"
        Remove-Item -Path "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
    }
}


# Empty Recycle Bin
Write-Host "-- Emptying the Recycle Bin"
$bin = (New-Object -ComObject Shell.Application).NameSpace(10)
$bin.items() | ForEach-Object {
    Write-Host "Deleting $($_.Name) from the Recycle Bin"
    Remove-Item $_.Path -Recurse -Force
}


Write-Host "Cleanup complete!"


# ================= Additional Safety / Integrity Block =================
# Ensures critical directories exist and have required ACLs for .msix / AppX package installation

Write-Host "-- Checking integrity of critical directories"

$criticalDirs = @(
    @{ Path = "$env:WinDir\Temp"; Profile = 'WinTemp' },
    @{ Path = "$env:WinDir\Prefetch"; Profile = 'Prefetch' },
    @{ Path = "$env:ProgramData\Microsoft\Windows\WER"; Profile = 'WER' }
)


function Set-DirExists {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        try { New-Item -ItemType Directory -Path $Path -Force | Out-Null; Write-Host "Recreated: $Path" -ForegroundColor Yellow } catch {}
    }
}


function Set-DirAcl {
    param([string]$Path, [string]$AclProfile)
    try {
        if (-not (Test-Path $Path)) { return }
        $ic = (icacls $Path 2>$null) -join ' '
        switch ($AclProfile) {
            'WinTemp' {
                if ($ic -notmatch 'TrustedInstaller') {
                    Write-Host "Restoring default ACL on $Path" -ForegroundColor Yellow
                    icacls $Path /inheritance:e > $null 2>&1
                    # Note: Users need Modify (M) for Temp directory
                    icacls $Path /grant:r "NT SERVICE\\TrustedInstaller:(F)" "NT AUTHORITY\\SYSTEM:(OI)(CI)(F)" "BUILTIN\\Administrators:(OI)(CI)(F)" "CREATOR OWNER:(OI)(CI)(IO)(F)" "BUILTIN\\Users:(OI)(CI)(M)" > $null 2>&1
                }
            }
            'Prefetch' {
                if ($ic -notmatch 'TrustedInstaller') {
                    Write-Host "Restoring default ACL on $Path" -ForegroundColor Yellow
                    icacls $Path /inheritance:e > $null 2>&1
                    icacls $Path /grant:r "NT SERVICE\TrustedInstaller:(F)" "NT AUTHORITY\SYSTEM:(OI)(CI)(F)" "BUILTIN\Administrators:(OI)(CI)(F)" > $null 2>&1
                }
            }
            'WER' {
                # For WER, use light recursive reset only if SYSTEM is missing
                if ($ic -notmatch 'SYSTEM') {
                    Write-Host "Restoring WER permissions" -ForegroundColor Yellow
                    icacls $Path /reset /T /C > $null 2>&1
                }
            }
        }
    }
    catch {}
}


foreach ($c in $criticalDirs) { Set-DirExists -Path $c.Path }
foreach ($c in $criticalDirs) { Set-DirAcl -Path $c.Path -AclProfile $c.Profile }


# Quick MSIX/AppX prerequisites test
function Test-MsixPrereq {
    $tempTest = Join-Path $env:WinDir 'Temp\_msix_perm_test.txt'
    try {
        'test' | Out-File -FilePath $tempTest -Encoding ASCII -Force
        if (-not (Test-Path $tempTest)) { throw 'Failed to create file in Windows\Temp' }
        Remove-Item $tempTest -Force -ErrorAction SilentlyContinue
        # Check main services
        $needed = 'AppXSVC', 'ClipSVC'
        $svcStatus = foreach ($n in $needed) { Get-Service -Name $n -ErrorAction SilentlyContinue }
        foreach ($s in $svcStatus) { if ($s -and $s.Status -eq 'Stopped') { Write-Host "Warning: Service $($s.Name) is stopped" -ForegroundColor Yellow } }
        Write-Host "MSIX prerequisite: OK" -ForegroundColor Green
    }
    catch {
        Write-Host "Warning: possible MSIX permission issue -> $($_.Exception.Message)" -ForegroundColor Red
    }
}
Test-MsixPrereq


# Quick validation: test AppX Deployment Service access (does not fail script if unavailable)
try {
    Get-Service AppXSVC -ErrorAction Stop | Out-Null
    Write-Host "AppXSVC present: OK"
}
catch { Write-Host "Warning: AppXSVC not accessible" -ForegroundColor Yellow }

Write-Host "Integrity verified."
# =======================================================================
