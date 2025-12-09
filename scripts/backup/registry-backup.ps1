#Requires -RunAsAdministrator

# ----------------------------
# Initial Setup
# ----------------------------
Clear-Host
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host "     COMPLETE BACKUP FOR REGISTRY TWEAKS      " -ForegroundColor Yellow
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host ""

# Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script must be run as Administrator."
    Start-Sleep -Seconds 10
    exit
}

# ----------------------------
# Backup Configuration
# ----------------------------
$backupBaseDir = "C:\Ryzen Optimizer\Backup"
$timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$folderName = "registry-$timestamp"
$backupDir = Join-Path -Path $backupBaseDir -ChildPath $folderName
New-Item -Path $backupDir -ItemType Directory -Force | Out-Null

Write-Host "Backup location will be: $backupDir" -ForegroundColor Cyan

# Define backup file paths
$regValuesBackupFile = Join-Path $backupDir "registry-values-backup.csv"
$tasksBackupFile = Join-Path $backupDir "registry-tasks-backup.csv"
$bcdBackupFile = Join-Path $backupDir "registry-bcd-backup.bin"
$removedKeysBackupFile = Join-Path $backupDir "registry-removedkeys-backup.reg"
$networkBackupFile = Join-Path $backupDir "registry-network-backup.csv"

# Arrays to hold backup data
$regBackupData = @()
$taskBackupData = @()
$networkBackupData = @()

#================================================================================
# HELPER FUNCTION TO GET REGISTRY VALUES
#================================================================================
function Get-RegistryValueBackup {
    param(
        [string]$Path,
        [string]$Name
    )
    $exists = $false
    $currentValue = $null
    $currentType = $null

    try {
        if (Test-Path $Path) {
            $property = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($null -ne $property) {
                $exists = $true
                $currentValue = $property.$Name
                $key = Get-Item -Path $Path
                $currentType = $key.GetValueKind($Name)
            }
        }
    }
    catch {
        Write-Warning "Could not read registry value: $Path \ $Name."
    }

    return [PSCustomObject]@{
        Path          = $Path
        Name          = $Name
        Value         = $currentValue
        Type          = $currentType
        ExistedBefore = $exists
    }
}


#================================================================================
# SCRIPT BODY - DATA COLLECTION
#================================================================================

# --- 1. BCDEdit Backup ---
Write-Host "--- Backing up Boot Configuration Data (BCD)..." -ForegroundColor Green
try {
    bcdedit.exe /export $bcdBackupFile | Out-Null
    Write-Host "BCD backup created successfully."
}
catch {
    Write-Error "Failed to create BCD backup. This is a critical step."
}

# --- 2. Backup of Registry Keys to be Removed ---
Write-Host "--- Backing up registry keys scheduled for removal..." -ForegroundColor Green
$keysToRemove = @(
    "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}",
    "HKCU:\System\GameConfigStore\Children",
    "HKCU:\System\GameConfigStore\Parents"
)
foreach ($key in $keysToRemove) {
    if (Test-Path $key) {
        try {
            $tempRegFile = Join-Path $env:TEMP "temp_reg_export.reg"
            reg.exe export "$key" "$tempRegFile" /y | Out-Null
            $content = Get-Content $tempRegFile
            Add-Content -Path $removedKeysBackupFile -Value $content
            Remove-Item $tempRegFile -Force
            Write-Host "Backed up key for removal: $key"
        }
        catch {
            Write-Warning "Could not back up key for removal: $key"
        }
    }
}

# --- 3. Scheduled Tasks Backup ---
Write-Host "--- Backing up Scheduled Tasks states..." -ForegroundColor Green
$tasksToManage = @(
    "\Microsoft\Windows\Defrag\ScheduledDefrag",
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "\Microsoft\Windows\Autochk\Proxy",
    "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
    "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
    "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
    "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM",
    "\Microsoft\Windows\Customer Experience Improvement Program\Uploader"
)
foreach ($taskName in $tasksToManage) {
    # The original script uses -TaskName, which can be ambiguous. We'll try it first, then by path.
    $task = Get-ScheduledTask -TaskName ($taskName.Split('\')[-1]) -ErrorAction SilentlyContinue
    if ($task) {
        $taskBackupData += [PSCustomObject]@{
            TaskName = $taskName # Use the full path for unambiguous restore
            State    = $task.State
        }
    }
}
Write-Host "Found and backed up $($taskBackupData.Count) scheduled tasks."

# --- 4. Network (DNS) Backup ---
Write-Host "--- Backing up current DNS settings..." -ForegroundColor Green
$activeInterfaces = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
foreach ($iface in $activeInterfaces) {
    $dnsInfo = Get-DnsClientServerAddress -InterfaceIndex $iface.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if ($dnsInfo) {
        $networkBackupData += [PSCustomObject]@{
            InterfaceIndex = $iface.InterfaceIndex
            DNSServers     = $dnsInfo.ServerAddresses -join ','
        }
    }
}
Write-Host "Found and backed up DNS settings for $($networkBackupData.Count) active interface(s)."

# --- 5. Registry Values Backup ---
Write-Host "--- Backing up all specified registry values (this may take a moment)..." -ForegroundColor Green
# <<< LISTA 100% COMPLETA extraída do seu script registry.ps1 >>>
$registryKeysToBackup = @(
    # [2/10] Privacy & Telemetry
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name="LetAppsRunInBackground"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"; Name="GlobalUserDisabled"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-338388Enabled"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-338389Enabled"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-338393Enabled"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name="NoAutoUpdate"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name="DoNotCompress"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"; Name="disabled"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoDriveTypeAutoRun"};
    @{Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoDriveTypeAutoRun"};

    # [3/10] UI & Explorer Tweaks
    @{Path="HKCU:\Control Panel\Desktop"; Name="MenuShowDelay"};
    @{Path="HKCU:\Control Panel\Desktop"; Name="ScreenSaveActive"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="ShowCopilotButton"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="TaskbarDa"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="ShowTaskViewButton"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings"; Name="TaskbarEndTask"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="HideFileExt"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete"; Name="Append Completion"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete"; Name="AutoSuggest"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="ExtendedUIHoverTime"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize"; Name="StartupDelayInMSec"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="SeparateProcess"};
    @{Path="HKCU:\Control Panel\Desktop"; Name="LowLevelHooksTimeout"};
    @{Path="HKCU:\Control Panel\Desktop"; Name="AutoEndTasks"};
    @{Path="HKCU:\Control Panel\Desktop"; Name="WaitToKillAppTimeout"};
    @{Path="HKCU:\Control Panel\Desktop"; Name="HungAppTimeout"};
    @{Path="HKCU:\Control Panel\Desktop"; Name="ForegroundLockTimeout"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="Hidden"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="LaunchTo"};

    # [4/10] Network Optimizations
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="DisableBandwidthThrottling"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="MaxCmds"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="TcpMaxHalfOpen"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="TcpMaxHalfOpenRetried"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="TcpMaxPortsExhausted"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="TcpNumConnections"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="EnableECN"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="TcpAckFrequency"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="TCPNoDelay"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="TcpTimedWaitDelay"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="DefaultTTL"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="EnablePMTUDiscovery"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="EnablePMTUBHDetect"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="SackOpts"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="DisableTaskOffload"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="EnableTCPChimney"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="EnableRSS"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"; Name="EnableTCPA"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched"; Name="NonBestEffortLimit"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"; Name="CacheHashTableBucketSize"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"; Name="CacheHashTableSize"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"; Name="MaxCacheEntryTtlLimit"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"; Name="MaxCacheTtl"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters"; Name="BufferAlignment"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters"; Name="DefaultReceiveWindow"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters"; Name="DefaultSendWindow"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters"; Name="DisableAddressSharing"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters"; Name="DisableChainedReceive"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters"; Name="disabledirectAcceptEx"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters"; Name="DoNotHoldNICBuffers"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters"; Name="DynamicSendBufferDisable"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters"; Name="FastSendDatagramThreshold"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters"; Name="FastCopyReceiveThreshold"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters"; Name="IgnoreOrderlyRelease"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters"; Name="IgnorePushBitOnReceives"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"; Name="NetworkThrottlingIndex"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"; Name="SystemResponsiveness"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters"; Name="KeyboardDataQueueSize"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"; Name="MouseDataQueueSize"};

    # [5/10] Gaming & GPU Optimizations
    @{Path="HKCU:\System\GameConfigStore"; Name="GameDVR_Enabled"};
    @{Path="HKCU:\System\GameConfigStore"; Name="GameDVR_FSEBehavior"};
    @{Path="HKCU:\System\GameConfigStore"; Name="GameDVR_FSEBehaviorMode"};
    @{Path="HKCU:\System\GameConfigStore"; Name="GameDVR_DXGIHonorFSEWindowsCompatible"};
    @{Path="HKCU:\System\GameConfigStore"; Name="GameDVR_HonorUserFSEBehaviorMode"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"; Name="AllowGameDVR"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"; Name="HwSchMode"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"; Name="DisableMultiplaneOverlay"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"; Name="Attributes"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"; Name="Affinity"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"; Name="Clock Rate"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"; Name="GPU Priority"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"; Name="Priority"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"; Name="Scheduling Category"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"; Name="SFIO Priority"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; Name="GPU_SCHEDULER_MODE"};
    @{Path="HKLM:\SOFTWARE\Microsoft\DirectX\UserGpuPreferences"; Name="DirectX12EnableHardwareProtected"};
    @{Path="HKCU:\Software\Microsoft\DirectX\UserGpuPreferences"; Name="GpuPreference"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule"; Name="WindowedGsyncGeforceFlag"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule"; Name="FrameRateMin"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule"; Name="IgnoreDisplayChangeDuration"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule"; Name="LingerInterval"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule"; Name="LicenseInterval"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule"; Name="RestrictedNvcplUIMode"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule"; Name="DisableSpecificPopups"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule"; Name="DisableExpirationPopups"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule"; Name="EnableForceIgpuDgpuFromUI"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule"; Name="HideXGpuTrayIcon"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule"; Name="ShowTrayIcon"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule"; Name="HideBalloonNotification"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule"; Name="PerformanceState"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule"; Name="Gc6State"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule"; Name="FrameDisplayBaseNegOffsetNS"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule"; Name="FrameDisplayResDivValue"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule"; Name="IgnoreNodeLocked"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule"; Name="IgnoreSP"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule"; Name="DontAskAgain"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power"; Name="DefaultD3TransitionLatencyActivelyUsed"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power"; Name="DefaultD3TransitionLatencyIdleLongTime"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power"; Name="DefaultD3TransitionLatencyIdleMonitorOff"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power"; Name="DefaultD3TransitionLatencyIdleNoContext"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power"; Name="DefaultD3TransitionLatencyIdleShortTime"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power"; Name="DefaultD3TransitionLatencyIdleVeryLongTime"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power"; Name="DefaultLatencyToleranceIdle0"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power"; Name="DefaultLatencyToleranceIdle0MonitorOff"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power"; Name="DefaultLatencyToleranceIdle1"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power"; Name="DefaultLatencyToleranceIdle1MonitorOff"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power"; Name="DefaultLatencyToleranceMemory"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power"; Name="DefaultLatencyToleranceNoContext"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power"; Name="DefaultLatencyToleranceNoContextMonitorOff"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power"; Name="DefaultLatencyToleranceOther"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power"; Name="DefaultLatencyToleranceTimerPeriod"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power"; Name="DefaultMemoryRefreshLatencyToleranceActivelyUsed"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power"; Name="DefaultMemoryRefreshLatencyToleranceMonitorOff"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power"; Name="DefaultMemoryRefreshLatencyToleranceNoContext"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power"; Name="Latency"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power"; Name="MaxIAverageGraphicsLatencyInOneBucket"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power"; Name="MiracastPerfTrackGraphicsLatency"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power"; Name="MonitorLatencyTolerance"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power"; Name="MonitorRefreshLatencyTolerance"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power"; Name="TransitionLatency"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\Dwm"; Name="FlipQueueSize"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"; Name="FrameLatency"};
    @{Path="HKLM:\SOFTWARE\Microsoft\DirectX"; Name="MaxFrameLatency"};
    @{Path="HKLM:\SOFTWARE\Microsoft\DirectX"; Name="DisableThreadedOptimizations"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Direct3D\Global"; Name="MaxQueuedFrames"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Direct3D\Global"; Name="EnableMultiThreadedRendering"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Direct3D\Global"; Name="DisableVSync"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Direct3D\Drivers"; Name="SoftwareOnly"};
    @{Path="HKLM:\SOFTWARE\Microsoft\DirectInput"; Name="EnableBackgroundProcessing"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"; Name="TdrDelay"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"; Name="TdrDdiDelay"};
    @{Path="HKLM:\SOFTWARE\AMD\CN"; Name="DisableDriverTelemetry"};
    @{Path="HKLM:\SOFTWARE\AMD\RadeonSettings"; Name="ShaderCache"};
    
    # [6/10] Memory & CPU Optimizations
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name="DisablePagingExecutive"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name="LargeSystemCache"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name="IoPageLockLimit"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name="featureSettings"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name="FeatureSettingsOverride"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Name="FeaturesSettingsOverrideMask"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl"; Name="Win32PrioritySeparation"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl"; Name="IRQ8Priority"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl"; Name="IRQ16Priority"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"; Name="EnablePrefetcher"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"; Name="EnableSuperfetch"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"; Name="EnableBoottrace"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583"; Name="ValueMax"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"; Name="TimerResolution"};

    # [7/10] Storage Optimizations
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"; Name="NtfsDisableLastAccessUpdate"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction"; Name="Enable"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"; Name="NTFSDisable8dot3NameCreation"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"; Name="NtfsMemoryUsage"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"; Name="DisableThrottle"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"; Name="Cpupriority"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"; Name="SerializeTimerExpiration"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control"; Name="SvcHostSplitThresholdInKB"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\USB"; Name="DisableSelectiveSuspend"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"; Name="KiClockTimerPerCpu"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"; Name="KiClockTimerHighLatency"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"; Name="KiClockTimerAlwaysOnPresent"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"; Name="ClockTimerPerCpu"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"; Name="ClockTimerHighLatency"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"; Name="ClockTimerAlwaysOnPresent"};
    
    # [8/10] Security Hardening
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="SMB1"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="SizReqBuf"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="IRPStackSize"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Name="EnableMulticast"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="DisableDomainCreds"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Name="EnableVirtualizationBasedSecurity"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Name="RequirePlatformSecurityFeatures"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"; Name="HVCIMATRequired"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\HypervisorEnforcedCodeIntegrity"; Name="Enabled"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"; Name="EnableVirtualizationBasedSecurity"};
    @{Path="HKLM:\System\CurrentControlSet\Control\Remote Assistance"; Name="fAllowToGetHelp"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="HideSCAMeetNow"};
    
    # [10/10] Final Tweaks
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling"; Name="PowerThrottlingOff"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\be337238-0d82-4146-a960-4f3749d470c7"; Name="Attributes"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1"; Name="DisableMultiplaneOverlay"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"; Name="HiberBootEnabled"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"; Name="CoalescingTimerInterval"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power"; Name="HibernateEnabled"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power"; Name="EnergyEstimationEnabled"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power"; Name="EnergySaverPolicy"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power"; Name="CsEnabled"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583"; Name="ValueMin"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\ea062031-0e34-4ff1-9b6d-eb1059334028"; Name="ACSettingIndex"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4ff1-9b6d-eb1059334028"; Name="DCSettingIndex"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100"; Name="Attributes"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100"; Name="Affinity"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100"; Name="Background Only"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100"; Name="Clock Rate"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100"; Name="GPU Priority"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100"; Name="Priority"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100"; Name="Scheduling Category"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100"; Name="SFIO Priority"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100"; Name="BackgroundPriority"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100"; Name="Latency Sensitive"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient"; Name="Enabled"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer"; Name="Enabled"};
    @{Path="HKCU:\Control Panel\Mouse"; Name="MouseSpeed"};
    @{Path="HKCU:\Control Panel\Mouse"; Name="MouseThreshold1"};
    @{Path="HKCU:\Control Panel\Mouse"; Name="MouseThreshold2"};
    @{Path="HKCU:\Control Panel\Mouse"; Name="MouseHoverTime"};
    @{Path="HKCU:\Control Panel\Mouse"; Name="SwapMouseButtons"};
    @{Path="HKCU:\Control Panel\Accessibility\MouseKeys"; Name="Flags"};
    @{Path="HKCU:\Control Panel\Accessibility\Keyboard Response"; Name="Flags"};
    @{Path="HKCU:\Control Panel\Accessibility\StickyKeys"; Name="Flags"};
    @{Path="HKCU:\Control Panel\Accessibility\ToggleKeys"; Name="Flags"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"; Name="TurnOffWindowsCopilot"};
    @{Path="HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot"; Name="TurnOffWindowsCopilot"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings"; Name="AutoOpenCopilotLargeScreens"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings"; Name="NOC_GLOBAL_SETTING_TOASTS_ENABLED"};
    @{Path="HKCU:\Software\Microsoft\Windows\Shell\Copilot\BingChat"; Name="IsUserEligible"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Dsh"; Name="AllowNewsAndInterests"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy"; Name="(Default)"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="EnableActivityFeed"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios"; Name="Value"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps"; Name="AllowUntriggeredNetworkTrafficOnSettingsPage"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps"; Name="AutoDownloadAndUpdateMapData"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"; Name="NoLockScreenCamera"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"; Name="Enabled"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy"; Name="01"};
    @{Path="HKLM:\SYSTEM\ControlSet001\Services\Ndu"; Name="Start"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\Dwm"; Name="OverlayTestMode"};
    @{Path="HKLM:\SOFTWARE\Microsoft\MSMQ"; Name="TCPNoDelay"};
    @{Path="HKLM:\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter"; Name="ActivationType"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="AllowCortana"};
    @{Path="HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR"; Name="value"};
    @{Path="HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\ApplicationManagement"; Name="AllowGameDVR"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR"; Name="AppCaptureEnabled"};
    @{Path="HKCU:\SOFTWARE\Microsoft\GameBar"; Name="AutoGameModeEnabled"};
    @{Path="HKCU:\SOFTWARE\Microsoft\GameBar"; Name="UseNexusForGameBarEnabled"};
    @{Path="HKCU:\SOFTWARE\Microsoft\GameBar"; Name="ShowStartupPanel"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Avalon.Graphics"; Name="DisableHWAcceleration"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Avalon.Graphics"; Name="MaxMultisampleType"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\SysMain"; Name="Start"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching"; Name="SearchOrderConfig"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance"; Name="MaintenanceDisabled"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control"; Name="WaitToKillServiceTimeout"};
    @{Path="HKCU:\Control Panel\Keyboard"; Name="InitialKeyboardIndicators"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power"; Name="ExitLatency"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power"; Name="ExitLatencyCheckEnabled"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power"; Name="Latency"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power"; Name="LatencyToleranceDefault"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power"; Name="LatencyToleranceFSVP"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power"; Name="LatencyTolerancePerfOverride"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power"; Name="LatencyToleranceScreenOffIR"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power"; Name="LatencyToleranceVSyncEnabled"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Power"; Name="RtlCapabilityCheckLatency"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\PrecisionTouchPad"; Name="EnablePrecision"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="TaskbarMn"}
)

# Adicionar chaves dinâmicas da interface de rede
$activeInterface = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.PhysicalMediaType -ne $null } | Select-Object -First 1
if ($activeInterface) {
    $InterfaceGUID = $activeInterface.InterfaceGuid
    if ($InterfaceGUID) {
        $registryKeysToBackup += @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$InterfaceGUID"; Name="TcpAckFrequency"}
        $registryKeysToBackup += @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$InterfaceGUID"; Name="TCPNoDelay"}
    }
}


$totalKeys = $registryKeysToBackup.Count
$processedKeys = 0
foreach ($keyInfo in $registryKeysToBackup) {
    $processedKeys++
    Write-Progress -Activity "Backing up Registry Values" -Status "Processing key $processedKeys of $totalKeys" -PercentComplete (($processedKeys / $totalKeys) * 100)
    $regBackupData += Get-RegistryValueBackup -Path $keyInfo.Path -Name $keyInfo.Name
}
Write-Host "Backed up $($regBackupData.Count) registry values."

#================================================================================
# SCRIPT COMPLETION - SAVING DATA
#================================================================================
Write-Host "--- Saving all backup data to files..." -ForegroundColor Green

if ($regBackupData.Count -gt 0) { $regBackupData | Export-Csv -Path $regValuesBackupFile -NoTypeInformation -Encoding UTF8 }
if ($taskBackupData.Count -gt 0) { $taskBackupData | Export-Csv -Path $tasksBackupFile -NoTypeInformation -Encoding UTF8 }
if ($networkBackupData.Count -gt 0) { $networkBackupData | Export-Csv -Path $networkBackupFile -NoTypeInformation -Encoding UTF8 }

Write-Host ""
Write-Host "==============================================" -ForegroundColor Green
Write-Host "            BACKUP PROCESS COMPLETE           " -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green
Write-Host "All specified system settings have been saved to:"
Write-Host "$backupDir" -ForegroundColor Yellow
Write-Host "You can now safely run the registry.ps1 script."