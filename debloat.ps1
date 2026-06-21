# ==============================================
# R Y Z E N Optimizer
# Version: 3.0 | Date: 2025-07-25
# ==============================================

[CmdletBinding()]
param(
    [switch]$All,
    [switch]$DisableXboxLoginFeatures,
    [switch]$DisableSystemDevices,
    [switch]$SkipMenu,
    [string]$DnsProvider = ''
)

# --- Administrator Check ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "`n[ERROR] This script requires administrator privileges." -ForegroundColor Red
    Write-Host "Please run as Administrator and try again.`n"
    Pause
    exit
}

# --- Import Shared Module ---
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Import-Module "$scriptDir\scripts\lib\RyzenOptimizer.psm1" -Force -ErrorAction Stop

# --- Initial Settings ---
$host.UI.RawUI.WindowTitle = "Ryzen Optimizer v3.0"
$version = "3.0"

# --- System Detection ---
$sysInfo = Get-SystemInfo

# --- Category Definitions ---
$categories = [ordered]@{
    '1' = @{ Name = 'System Cleanup';          Enabled = $true;  Key = 'cleanup' }
    '2' = @{ Name = 'Remove Bloatware';        Enabled = $true;  Key = 'bloatware' }
    '3' = @{ Name = 'Network Optimizations';   Enabled = $true;  Key = 'network' }
    '4' = @{ Name = 'Gaming Tweaks';           Enabled = $true;  Key = 'gaming' }
    '5' = @{ Name = 'Privacy and Telemetry';   Enabled = $true;  Key = 'privacy' }
    '6' = @{ Name = 'Power and CPU Settings';  Enabled = $true;  Key = 'power' }
    '7' = @{ Name = 'UI and Explorer Tweaks';  Enabled = $true;  Key = 'ui' }
    '8' = @{ Name = 'Security Hardening';      Enabled = $true;  Key = 'security' }
}

# Optional toggles
$optionals = [ordered]@{
    'S' = @{ Name = 'Disable Microsoft Store';     Enabled = $false; Warning = $false }
    'G' = @{ Name = 'Disable Xbox (App+Services)'; Enabled = $false; Warning = $false }
    'D' = @{ Name = 'Disable Windows Defender RT';  Enabled = $false; Warning = $true }
    'N' = @{ Name = 'Disable Notifications';        Enabled = $false; Warning = $false }
    'M' = @{ Name = 'Disable Spectre Mitigations';  Enabled = $false; Warning = $true }
    'Y' = @{ Name = 'Disable Selected System Devices'; Enabled = $true; Warning = $true }
}

# Fix scripts
$fixes = [ordered]@{
    'F1' = @{ Name = 'Repair Xbox Login';           Script = 'scripts\fixes\repair-xbox-login.ps1' }
    'F2' = @{ Name = 'Restore Xbox + Store';        Script = 'scripts\fixes\restore-xbox-store.ps1' }
    'F3' = @{ Name = 'Restore System Devices';      Script = 'scripts\backup\devices-restore.ps1' }
}

# DNS options
# 1-3: plain resolvers. 4-5: filtering resolvers that block ads/malware at the
# resolver level (no large hosts file, zero DNS-parse overhead). The hosts file
# stays small (telemetry only); ads/malware are filtered upstream by the resolver.
$dnsOptions = [ordered]@{
    1 = @{ Name = "Google";              Primary = "8.8.8.8";       Secondary = "8.8.4.4" }
    2 = @{ Name = "Cloudflare";          Primary = "1.1.1.1";       Secondary = "1.0.0.1" }
    3 = @{ Name = "Quad9 (malware)";     Primary = "9.9.9.9";       Secondary = "149.112.112.112" }
    4 = @{ Name = "AdGuard (ads+malware)"; Primary = "94.140.14.14"; Secondary = "94.140.15.15" }
    5 = @{ Name = "Cloudflare (malware)";  Primary = "1.1.1.2";      Secondary = "1.0.0.2" }
}
# Default: AdGuard filtering resolver (ads + malware) - option 4.
$selectedDns = 4

# --- Menu Functions ---
function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  +=======================================================+" -ForegroundColor DarkCyan
    Write-Host "  |" -NoNewline -ForegroundColor DarkCyan
    Write-Host "            R Y Z E N  O P T I M I Z E R              " -NoNewline -ForegroundColor Cyan
    Write-Host "|" -ForegroundColor DarkCyan
    Write-Host "  |" -NoNewline -ForegroundColor DarkCyan
    Write-Host "                    Version $version                       " -NoNewline -ForegroundColor DarkGray
    Write-Host "|" -ForegroundColor DarkCyan
    Write-Host "  +=======================================================+" -ForegroundColor DarkCyan
}

function Show-SystemInfo {
    $osShort = "Windows 10"
    if ($sysInfo.IsWin11) { $osShort = "Windows 11" }
    $cpuShort = $sysInfo.CPUName
    if ($cpuShort.Length -gt 30) { $cpuShort = $cpuShort.Substring(0, 30) + "..." }

    Write-Host "  |" -NoNewline -ForegroundColor DarkCyan
    $info1 = "  $osShort | $cpuShort"
    $pad1 = 55 - $info1.Length
    if ($pad1 -lt 0) { $pad1 = 0 }
    Write-Host "$info1$(' ' * $pad1)" -NoNewline -ForegroundColor DarkGray
    Write-Host "|" -ForegroundColor DarkCyan

    Write-Host "  |" -NoNewline -ForegroundColor DarkCyan
    $info2 = "  GPU: $($sysInfo.GPUVendor) | RAM: $($sysInfo.RAMTotal)GB | Disk: $($sysInfo.DiskType)"
    if ($info2.Length -gt 55) { $info2 = $info2.Substring(0, 55) }
    $pad2 = 55 - $info2.Length
    if ($pad2 -lt 0) { $pad2 = 0 }
    Write-Host "$info2$(' ' * $pad2)" -NoNewline -ForegroundColor DarkGray
    Write-Host "|" -ForegroundColor DarkCyan
    Write-Host "  +=======================================================+" -ForegroundColor DarkCyan
}

function Show-Menu {
    Show-Banner
    Show-SystemInfo

    Write-Host "  |" -NoNewline -ForegroundColor DarkCyan
    Write-Host "  OPTIMIZATION CATEGORIES:                                " -NoNewline -ForegroundColor White
    Write-Host "|" -ForegroundColor DarkCyan
    Write-Host "  |  ---------------------------------------------------  |" -ForegroundColor DarkGray

    foreach ($key in $categories.Keys) {
        $cat = $categories[$key]
        if ($cat.Enabled) { $status = '[ON] '; $color = 'Green' }
        else              { $status = '[OFF]'; $color = 'DarkGray' }
        $label = "  [$key] $($cat.Name)"
        $pad = 47 - $label.Length
        if ($pad -lt 0) { $pad = 0 }

        Write-Host '  |' -NoNewline -ForegroundColor DarkCyan
        Write-Host "$label$(' ' * $pad)" -NoNewline -ForegroundColor White
        Write-Host "$status" -NoNewline -ForegroundColor $color
        Write-Host '   |' -ForegroundColor DarkCyan
    }

    Write-Host "  |  ---------------------------------------------------  |" -ForegroundColor DarkGray
    Write-Host "  |" -NoNewline -ForegroundColor DarkCyan
    Write-Host "  OPTIONAL (toggle with letter key):                      " -NoNewline -ForegroundColor Yellow
    Write-Host "|" -ForegroundColor DarkCyan

    foreach ($key in $optionals.Keys) {
        $opt = $optionals[$key]
        if ($opt.Enabled) { $status = "[ON] "; $color = "Yellow" }
        else              { $status = "[OFF]"; $color = "DarkGray" }
        $warnTag = "  "
        if ($opt.Warning -and $opt.Enabled) { $warnTag = " !" }
        $label = "  [$key] $($opt.Name)"
        $pad = 45 - $label.Length
        if ($pad -lt 0) { $pad = 0 }

        Write-Host "  |" -NoNewline -ForegroundColor DarkCyan
        Write-Host "$label$(' ' * $pad)" -NoNewline -ForegroundColor White
        Write-Host "$warnTag" -NoNewline -ForegroundColor Red
        Write-Host "$status" -NoNewline -ForegroundColor $color
        Write-Host "   |" -ForegroundColor DarkCyan
    }

    # DNS Selection
    $dnsName = $dnsOptions[$selectedDns].Name
    Write-Host "  |  ---------------------------------------------------  |" -ForegroundColor DarkGray
    Write-Host "  |" -NoNewline -ForegroundColor DarkCyan
    $dnsLabel = "  [P] DNS Provider: $dnsName"
    $dpad = 55 - $dnsLabel.Length
    if ($dpad -lt 0) { $dpad = 0 }
    Write-Host "$dnsLabel$(' ' * $dpad)" -NoNewline -ForegroundColor Cyan
    Write-Host "|" -ForegroundColor DarkCyan

    # FIXES section
    Write-Host "  |  ---------------------------------------------------  |" -ForegroundColor DarkGray
    Write-Host "  |" -NoNewline -ForegroundColor DarkCyan
    Write-Host "  FIXES (run standalone repair scripts):                   " -NoNewline -ForegroundColor Magenta
    Write-Host "|" -ForegroundColor DarkCyan
    foreach ($fkey in $fixes.Keys) {
        $fix = $fixes[$fkey]
        $flabel = "  [$fkey] $($fix.Name)"
        $fpad = 55 - $flabel.Length
        if ($fpad -lt 0) { $fpad = 0 }
        Write-Host "  |" -NoNewline -ForegroundColor DarkCyan
        Write-Host "$flabel$(' ' * $fpad)" -NoNewline -ForegroundColor White
        Write-Host "|" -ForegroundColor DarkCyan
    }

    Write-Host "  +=======================================================+" -ForegroundColor DarkCyan
    Write-Host "  |" -NoNewline -ForegroundColor DarkCyan
    Write-Host "  [A] Select All   [O] Deselect All   [B] Backup Only    " -NoNewline -ForegroundColor White
    Write-Host "|" -ForegroundColor DarkCyan
    Write-Host "  |" -NoNewline -ForegroundColor DarkCyan
    Write-Host "  [R] " -NoNewline -ForegroundColor Green
    Write-Host "RUN SELECTED" -NoNewline -ForegroundColor Green
    Write-Host "               [Q] " -NoNewline -ForegroundColor White
    Write-Host "Exit" -NoNewline -ForegroundColor Red
    Write-Host "                 |" -ForegroundColor DarkCyan
    Write-Host "  +=======================================================+" -ForegroundColor DarkCyan
    Write-Host ""
}

# --- Execution Functions ---
function Invoke-AllBackups {
    Write-Host "`n[BACKUP] Running all backup scripts..." -ForegroundColor Yellow

    $backupScripts = @(
        @{ Name = 'Registry';  Path = Join-Path $scriptDir 'scripts\backup\registry-backup.ps1' },
        @{ Name = 'Telemetry'; Path = Join-Path $scriptDir 'scripts\backup\telemetry-backup.ps1' },
        @{ Name = 'Services';  Path = Join-Path $scriptDir 'scripts\backup\services-backup.ps1' }
    )

    if ($optionals.Contains('Y') -and $optionals.Y.Enabled) {
        $backupScripts += @{ Name = 'System Devices'; Path = Join-Path $scriptDir 'scripts\backup\devices-backup.ps1' }
    }

    foreach ($backup in $backupScripts) {
        if (Test-Path $backup.Path) {
            Write-Host "  Backing up $($backup.Name)..." -ForegroundColor Cyan
            try { & $backup.Path }
            catch { Write-Warning "  $($backup.Name) backup failed: $($_.Exception.Message)" }
        } else {
            Write-Warning "  Backup script not found: $($backup.Path)"
        }
    }

    Write-Host "[OK] All backups completed." -ForegroundColor Green
}

function Invoke-Cleanup {
    Write-Host "`n[STEP 1] System Cleanup..." -ForegroundColor Green
    $removeTempPath = Join-Path $scriptDir "scripts\cleanup\remove-temp.ps1"
    if (Test-Path $removeTempPath) { & $removeTempPath }
    Write-Host "Running Disk Cleanup..."
    cleanmgr /verylowdisk

    # Free ~7GB by disabling Reserved Storage.
    Write-Host "Disabling Reserved Storage..."
    dism /Online /Set-ReservedStorageState /State:Disabled 2>$null

    # Reclaim space from the component store (superseded update payloads).
    # /ResetBase prevents uninstalling already-installed updates - acceptable for
    # a perf-focused setup, but you cannot roll those specific updates back after.
    Write-Host "Cleaning up component store (WinSxS)... this can take several minutes."
    dism /Online /Cleanup-Image /StartComponentCleanup /ResetBase 2>$null
}

function Invoke-Bloatware {
    param([bool]$DisableStore, [bool]$DisableXbox)
    Write-Host "`n[STEP 2] Removing Bloatware..." -ForegroundColor Green

    $removeAppsPath = Join-Path $scriptDir "scripts\bloatware\remove-apps.ps1"
    if (Test-Path $removeAppsPath) {
        $appParams = @{}
        if ($DisableXbox) { $appParams['RemoveXboxComponents'] = $true }
        if (-not $DisableStore) { $appParams['KeepMicrosoftStore'] = $true }
        if (-not $DisableXbox) { $appParams['KeepXboxApps'] = $true }
        & $removeAppsPath @appParams
    }
    $removeEdgePath = Join-Path $scriptDir "scripts\bloatware\remove-edge.ps1"
    if (Test-Path $removeEdgePath) {
        Unblock-File -Path $removeEdgePath -ErrorAction SilentlyContinue
        & $removeEdgePath
    }
    if ($DisableXbox) {
        $gamebarPath = Join-Path $scriptDir "scripts\bloatware\remove-gamebar-annoyance.bat"
        if (Test-Path $gamebarPath) { cmd.exe /c "`"$gamebarPath`"" }
    }
    $removeOneDrivePath = Join-Path $scriptDir "scripts\bloatware\remove-onedrive.ps1"
    if (Test-Path $removeOneDrivePath) { & $removeOneDrivePath }
}

function Invoke-NetworkOptimization {
    param([int]$DnsChoice)
    Write-Host "`n[STEP 3] Network Optimizations..." -ForegroundColor Green
    Write-Host "Resetting TCP/IP settings..."
    ipconfig /flushdns
    ipconfig /release
    ipconfig /renew
    $activeNet = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface } | Select-Object -First 1
    $ifName = "Ethernet"
    if ($activeNet) { $ifName = $activeNet.Name }
    $dns = $dnsOptions[$DnsChoice]
    netsh interface ip set dns name="$ifName" static $($dns.Primary)
    netsh interface ip add dns name="$ifName" $($dns.Secondary) index=2
    # Keep TCP auto-tuning ENABLED: disabling it caps the TCP receive window and
    # hurts throughput for wireless VR streaming (Quest Air Link / Virtual Desktop).
    netsh int tcp set global autotuninglevel=normal
    Write-Host "DNS set to $($dns.Name) ($($dns.Primary), $($dns.Secondary))" -ForegroundColor Green
    if ($DnsChoice -ge 4) {
        Write-Host "  Ads/malware filtered at the DNS resolver (no hosts-file overhead)." -ForegroundColor DarkCyan
    }
}

function Invoke-GamingTweaks {
    Write-Host "`n[STEP 4] Gaming and Registry Tweaks..." -ForegroundColor Green
    $registryPath = Join-Path $scriptDir "scripts\main\registry.ps1"
    if (Test-Path $registryPath) { & $registryPath -SkipBackup }

    # Enable MSI mode on the GPU (reduces DPC latency / micro-stutter).
    $msiPath = Join-Path $scriptDir "scripts\main\gpu-msi-mode.ps1"
    if (Test-Path $msiPath) { & $msiPath }
}

function Invoke-PrivacyTelemetry {
    Write-Host "`n[STEP 5] Privacy and Telemetry..." -ForegroundColor Green
    $telemetryPath = Join-Path $scriptDir "scripts\main\telemetry.ps1"
    if (Test-Path $telemetryPath) { & $telemetryPath -SkipBackup }
}

function Invoke-PowerCPU {
    Write-Host "`n[STEP 6] Power and CPU Settings..." -ForegroundColor Green
    $servicesPath = Join-Path $scriptDir "scripts\main\services.ps1"
    if (Test-Path $servicesPath) {
        if ($optionals.G.Enabled) { & $servicesPath -DisableXboxLoginFeatures -SkipBackup }
        else { & $servicesPath -SkipBackup }
    }
    if ($optionals.Y.Enabled) {
        $devicesPath = Join-Path $scriptDir "scripts\main\system-devices.ps1"
        if (Test-Path $devicesPath) { & $devicesPath -SkipBackup }
        else { Write-Warning "System devices script not found: $devicesPath" }
    }
    Write-Host "Activating Ultimate Performance mode..."
    try {
        $scheme = powercfg -list | Select-String 'Ultimate Performance'
        if (-not $scheme) {
            powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 | Out-Null
        }
        $schemeGuid = (powercfg -list | Select-String 'Ultimate Performance').ToString() -replace '.*\s(\{.*\})','${1}'
        powercfg -setactive $schemeGuid
    } catch {
        Write-Warning "Failed to activate Ultimate Performance power plan."
    }
    Write-Host "Disabling hibernation..."
    powercfg /hibernate off
}

function Invoke-UITweaks {
    Write-Host "`n[STEP 7] UI and Explorer Tweaks..." -ForegroundColor Green
    Write-Host "  UI tweaks are applied via registry.ps1 in Gaming Tweaks step." -ForegroundColor DarkGray
}

function Invoke-SecurityHardening {
    Write-Host "`n[STEP 8] Security Hardening..." -ForegroundColor Green
    Write-Host "  Security tweaks are applied via registry.ps1 in Gaming Tweaks step." -ForegroundColor DarkGray
    Write-Host "Disabling Internet Explorer..."
    dism /online /Remove-Capability /CapabilityName:Browser.InternetExplorer~~~~0.0.11.0 /NoRestart 2>$null
    Write-Host "Disabling Hyper-V..."
    dism /online /Disable-Feature /FeatureName:Microsoft-Hyper-V-All /NoRestart 2>$null

    # Windows Media Player: feature name differs between Win10 and Win11 24H2+
    Write-Host "Disabling Windows Media Player..."
    $wmpFeature = dism /online /Get-FeatureInfo /FeatureName:WindowsMediaPlayer 2>&1
    if ($LASTEXITCODE -eq 0) {
        dism /online /Disable-Feature /FeatureName:WindowsMediaPlayer /NoRestart 2>$null
    } else {
        # Try removing via capability (Win11 24H2+)
        $wmpCap = Get-WindowsCapability -Online -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'Media.WindowsMediaPlayer*' -and $_.State -eq 'Installed' }
        if ($wmpCap) {
            $wmpCap | ForEach-Object {
                Write-Host "  Removing capability: $($_.Name)" -ForegroundColor Cyan
                Remove-WindowsCapability -Online -Name $_.Name -ErrorAction SilentlyContinue | Out-Null
            }
        } else {
            Write-Host "  Windows Media Player not found (already removed or not available)." -ForegroundColor DarkGray
        }
    }

    Write-Host "Disabling Recall..."
    dism /online /Disable-Feature /FeatureName:Recall /NoRestart 2>$null
}

function Invoke-OptionalDefender {
    Write-Host "`n[OPTIONAL] Disabling Windows Defender Real-time..." -ForegroundColor Yellow
    Write-Host "  WARNING: This reduces system security!" -ForegroundColor Red
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
        Set-MpPreference -DisableIntrusionPreventionSystem $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue
        Write-Host "  Windows Defender real-time protection disabled." -ForegroundColor Yellow
    } catch {
        Write-Warning "  Could not disable Defender (may require Tamper Protection off)."
    }
}

function Invoke-OptionalNotifications {
    Write-Host "`n[OPTIONAL] Disabling Notifications..." -ForegroundColor Yellow
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type "DWord" -Value 0
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_TOASTS_ENABLED" -Type "DWord" -Value 0
    Write-Host "  Notifications disabled." -ForegroundColor Green
}

function Invoke-OptionalSpectre {
    Write-Host "`n[OPTIONAL] Disabling Spectre/Meltdown Mitigations..." -ForegroundColor Yellow
    Write-Host "  WARNING: This is a security risk but improves CPU performance 2-5 percent!" -ForegroundColor Red
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -Type "DWord" -Value 3
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -Type "DWord" -Value 3
    Write-Host "  CPU mitigations disabled." -ForegroundColor Yellow
}

function Invoke-Finalization {
    Write-Host "`n[FINAL] Finalizing..." -ForegroundColor Green
    Write-Host "Checking system integrity..."
    sfc /scannow
    Write-Host "Optimizing storage..."
    defrag C: /O /U
    Write-Host "Restarting audio service..."
    Stop-Service -Name "Audiosrv" -Force -ErrorAction SilentlyContinue
    Start-Service -Name "Audiosrv" -ErrorAction SilentlyContinue
}

function Invoke-RestorePoint {
    Write-Host "`n[BACKUP] Creating restore point..." -ForegroundColor Yellow
    try {
        Enable-ComputerRestore -Drive $env:SystemDrive -ErrorAction Stop
        Checkpoint-Computer -Description 'Pre-Debloat-v3' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
        Write-Host "[OK] Restore point created." -ForegroundColor Green
    } catch {
        Write-Warning "Failed to create restore point."
    }
}

# --- Main Execution ---
function Invoke-SelectedOptimizations {
    $disableStore = $optionals.S.Enabled
    $disableXbox = $optionals.G.Enabled

    Write-Host ""
    Write-Host "==============================================" -ForegroundColor Green
    Write-Host "       STARTING OPTIMIZATION PROCESS" -ForegroundColor Green
    Write-Host "==============================================" -ForegroundColor Green

    Invoke-RestorePoint
    Invoke-AllBackups

    $totalSteps = ($categories.Values | Where-Object { $_.Enabled }).Count
    $currentStep = 0

    if ($categories['1'].Enabled) { $currentStep++; Show-Progress -Current $currentStep -Total $totalSteps -Activity "System Cleanup"; Invoke-Cleanup }
    if ($categories['2'].Enabled) { $currentStep++; Show-Progress -Current $currentStep -Total $totalSteps -Activity "Remove Bloatware"; Invoke-Bloatware -DisableStore $disableStore -DisableXbox $disableXbox }
    if ($categories['3'].Enabled) { $currentStep++; Show-Progress -Current $currentStep -Total $totalSteps -Activity "Network Optimizations"; Invoke-NetworkOptimization -DnsChoice $selectedDns }
    if ($categories['4'].Enabled) { $currentStep++; Show-Progress -Current $currentStep -Total $totalSteps -Activity "Gaming Tweaks"; Invoke-GamingTweaks }
    if ($categories['5'].Enabled) { $currentStep++; Show-Progress -Current $currentStep -Total $totalSteps -Activity "Privacy and Telemetry"; Invoke-PrivacyTelemetry }
    if ($categories['6'].Enabled) { $currentStep++; Show-Progress -Current $currentStep -Total $totalSteps -Activity "Power and CPU"; Invoke-PowerCPU }
    if ($categories['7'].Enabled) { $currentStep++; Show-Progress -Current $currentStep -Total $totalSteps -Activity "UI Tweaks"; Invoke-UITweaks }
    if ($categories['8'].Enabled) { $currentStep++; Show-Progress -Current $currentStep -Total $totalSteps -Activity "Security Hardening"; Invoke-SecurityHardening }

    # Optional: Disable Xbox functionality (services, hosts, registry)
    if ($disableXbox) {
        Write-Host "`n[OPTIONAL] Disabling Xbox functionality (services, login, apps)..." -ForegroundColor Yellow
        $xboxDisablePath = Join-Path $scriptDir 'scripts\fixes\disable-xbox-login-features.ps1'
        if (Test-Path $xboxDisablePath) { & $xboxDisablePath }
        $xboxStoreDisablePath = Join-Path $scriptDir 'scripts\fixes\disable-xbox-store-features.ps1'
        if (Test-Path $xboxStoreDisablePath) { & $xboxStoreDisablePath }
    }

    # Optional: Disable Microsoft Store functionality
    if ($disableStore) {
        Write-Host "`n[OPTIONAL] Disabling Microsoft Store functionality..." -ForegroundColor Yellow
        $storeDisablePath = Join-Path $scriptDir 'scripts\fixes\disable-xbox-store-features.ps1'
        if (Test-Path $storeDisablePath) { & $storeDisablePath }
    }

    if ($optionals.D.Enabled) { Invoke-OptionalDefender }
    if ($optionals.N.Enabled) { Invoke-OptionalNotifications }
    if ($optionals.M.Enabled) { Invoke-OptionalSpectre }

    Invoke-Finalization

    # Summary
    $counters = Get-OptimizerCounters
    Write-Host ""
    Write-Host "==============================================" -ForegroundColor Green
    Write-Host "      OPTIMIZATION COMPLETED SUCCESSFULLY!" -ForegroundColor Green
    Write-Host "==============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "  Registry changes:  $($counters.RegistrySuccess) OK / $($counters.RegistryFail) failed" -ForegroundColor White
    Write-Host "  Service changes:   $($counters.ServiceSuccess) OK / $($counters.ServiceFail) failed" -ForegroundColor White
    Write-Host "  Task changes:      $($counters.TaskSuccess) OK / $($counters.TaskFail) failed" -ForegroundColor White
    Write-Host ""
    Write-Host "Recommendations:" -ForegroundColor Yellow
    Write-Host "  1. Restart your computer."
    Write-Host "  2. Check if all drivers are updated."
    Write-Host "  3. Configure your essential programs."
    Write-Host ""
    Pause

    Write-Host "Restarting Explorer..."
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
    Start-Process explorer.exe
}

# --- CLI Mode ---
if ($All -or $SkipMenu) {
    if ($DisableXboxLoginFeatures) { $optionals.G.Enabled = $true }
    if ($DisableSystemDevices) { $optionals.Y.Enabled = $true }
    if ($DnsProvider -match '^(2|cloudflare)$') { $selectedDns = 2 }
    elseif ($DnsProvider -match '^(3|quad9)$') { $selectedDns = 3 }
    elseif ($DnsProvider -match '^(4|adguard)$') { $selectedDns = 4 }
    elseif ($DnsProvider -match '^(5|cloudflare-malware|family)$') { $selectedDns = 5 }
    Invoke-SelectedOptimizations
    exit 0
}

# --- Interactive Menu Loop ---
do {
    Show-Menu
    $choice = Read-Host "  Select option"

    switch ($choice.ToUpper()) {
        { $_ -match '^[1-8]$' } {
            $categories[$_].Enabled = -not $categories[$_].Enabled
        }
        'S' { $optionals.S.Enabled = -not $optionals.S.Enabled }
        'G' { $optionals.G.Enabled = -not $optionals.G.Enabled }
        'D' {
            if (-not $optionals.D.Enabled) {
                Write-Host "`n  WARNING: Disabling Windows Defender reduces security!" -ForegroundColor Red
                $confirm = Read-Host "  Are you sure? (Y/N)"
                if ($confirm -match '^[YySs]$') { $optionals.D.Enabled = $true }
            } else { $optionals.D.Enabled = $false }
        }
        'N' { $optionals.N.Enabled = -not $optionals.N.Enabled }
        'M' {
            if (-not $optionals.M.Enabled) {
                Write-Host "`n  WARNING: Disabling CPU mitigations is a security risk!" -ForegroundColor Red
                $confirm = Read-Host "  Are you sure? (Y/N)"
                if ($confirm -match '^[YySs]$') { $optionals.M.Enabled = $true }
            } else { $optionals.M.Enabled = $false }
        }
        'Y' {
            if (-not $optionals.Y.Enabled) {
                Write-Host "`n  WARNING: This disables selected System Devices in Device Manager." -ForegroundColor Red
                Write-Host "  It may affect Hyper-V, RDP redirection, virtual drives, HPET, or composite devices." -ForegroundColor Red
                $confirm = Read-Host "  Are you sure? (Y/N)"
                if ($confirm -match '^[YySs]$') { $optionals.Y.Enabled = $true }
            } else { $optionals.Y.Enabled = $false }
        }
        'P' {
            $selectedDns++
            if ($selectedDns -gt $dnsOptions.Count) { $selectedDns = 1 }
            Write-Host "  DNS changed to: $($dnsOptions[$selectedDns].Name)" -ForegroundColor Cyan
            Start-Sleep -Milliseconds 500
        }
        'A' { foreach ($k in $categories.Keys) { $categories[$k].Enabled = $true } }
        'O' { foreach ($k in $categories.Keys) { $categories[$k].Enabled = $false } }
        'B' {
            Invoke-RestorePoint
            Write-Host "`nBackup completed. Press any key to return..." -ForegroundColor Green
            Pause
        }
        'R' {
            $enabledCount = ($categories.Values | Where-Object { $_.Enabled }).Count
            if ($enabledCount -eq 0) {
                Write-Host "`n  No categories selected! Enable at least one." -ForegroundColor Red
                Start-Sleep -Seconds 2
            } else {
                Write-Host "`n  Running $enabledCount optimization categories..." -ForegroundColor Green
                Start-Sleep -Seconds 1
                Invoke-SelectedOptimizations
                exit 0
            }
        }
        'Q' {
            Write-Host "`n  Exiting Ryzen Optimizer. No changes made." -ForegroundColor DarkGray
            exit 0
        }
        # Fix scripts
        { $fixes.Contains($_) } {
            $fixKey = $_
            $fix = $fixes[$fixKey]
            $fixPath = Join-Path $scriptDir $fix.Script
            if (Test-Path $fixPath) {
                Write-Host "`n  Running: $($fix.Name)..." -ForegroundColor Magenta
                & $fixPath
                Write-Host "`n  Fix completed. Press any key to return..." -ForegroundColor Green
                Pause
            } else {
                Write-Host "`n  Fix script not found: $($fix.Script)" -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
        default {
            Write-Host "`n  Invalid option. Try again." -ForegroundColor Red
            Start-Sleep -Milliseconds 800
        }
    }
} while ($true)
