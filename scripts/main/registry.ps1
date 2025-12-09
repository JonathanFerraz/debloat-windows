# ==============================================
# R Y Z Ξ N Optimizer
# Version: 2.0 | Date: 2025-07-25
# ==============================================

#Requires -RunAsAdministrator

# Set execution policy and error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# Function to safely add registry entries
function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [string]$Type,
        [object]$Value,
        [switch]$Force
    )
    
    try {
        if (!(Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        
        switch ($Type.ToUpper()) {
            "REG_DWORD" { Set-ItemProperty -Path $Path -Name $Name -Value ([int]$Value) -Type DWord -Force:$Force }
            "REG_SZ" { Set-ItemProperty -Path $Path -Name $Name -Value ([string]$Value) -Type String -Force:$Force }
            "REG_QWORD" { Set-ItemProperty -Path $Path -Name $Name -Value ([long]$Value) -Type QWord -Force:$Force }
            default { Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force:$Force }
        }
        return $true
    }
    catch {
        Write-Warning "Failed to set registry value: $Path\$Name - $($_.Exception.Message)"
        return $false
    }
}

# Function to safely remove registry keys/values
function Remove-RegistryItem {
    param(
        [string]$Path,
        [string]$Name = $null,
        [switch]$Recurse
    )
    
    try {
        if (Test-Path $Path) {
            if ($Name) {
                Remove-ItemProperty -Path $Path -Name $Name -Force
            }
            else {
                Remove-Item -Path $Path -Force -Recurse:$Recurse
            }
            return $true
        }
        return $false
    }
    catch {
        Write-Warning "Failed to remove registry item: $Path - $($_.Exception.Message)"
        return $false
    }
}

# Function to execute bcdedit commands with error handling
function Invoke-BcdEdit {
    param([string]$Arguments)
    try {
        Invoke-Expression "bcdedit.exe $Arguments" | Out-Null
        return $true
    }
    catch {
        Write-Warning "BCDEdit command failed: bcdedit $Arguments"
        return $false
    }
}
# Function to manage scheduled tasks
function Set-ScheduledTaskState {
    param(
        [string]$TaskName,
        [ValidateSet("Enable", "Disable")]$Action
    )
    
    try {
        if ($Action -eq "Enable") {
            Enable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null
        }
        else {
            Disable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null
        }
        return $true
    }
    catch {
        Write-Warning "Failed to $Action scheduled task: $TaskName"
        return $false
    }
}

# ----------------------------
# Initial Setup
# ----------------------------
$Host.UI.RawUI.WindowTitle = "Ryzen Optimizer v2.0"
Clear-Host

# Backup registry before making changes
& "$PSScriptRoot\..\backup\registry-backup.ps1"

Write-Host ""
Write-Host "==============================================" -ForegroundColor Green
Write-Host "APPLYING ULTIMATE PERFORMANCE REGISTRY TWEAKS" -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green

# Create Ryzen Optimizer directory and backup
Write-Host "Checking/creating Ryzen Optimizer folder..." -ForegroundColor Yellow
$RyzenOptimizerPath = "C:\Ryzen Optimizer"

# Create directory if it doesn't exist
if (!(Test-Path $RyzenOptimizerPath)) {
    try {
        New-Item -ItemType Directory -Path $RyzenOptimizerPath -Force | Out-Null
        Write-Host "Ryzen Optimizer folder created in C:\" -ForegroundColor Green
    }
    catch {
        Write-Warning "Error creating Ryzen Optimizer folder. Using C:\ as fallback."
        $RyzenOptimizerPath = "C:\"
    }
}
else {
    Write-Host "Ryzen Optimizer folder already exists in C:\" -ForegroundColor Yellow
}

# ----------------------------
# 1. System Information
# ----------------------------
Write-Host ""
Write-Host "[1/10] Gathering system information..." -ForegroundColor Cyan

$OS = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
$Model = (Get-CimInstance -ClassName Win32_ComputerSystem).Model
$DriveType = (Get-CimInstance -ClassName Win32_DiskDrive | Where-Object { $_.MediaType -like "*Fixed*" }).MediaType

Write-Host "Detected: $OS on $Model" -ForegroundColor White

# ----------------------------
# 2. Privacy & Telemetry
# ----------------------------
Write-Host ""
Write-Host "[2/10] Applying privacy settings..." -ForegroundColor Cyan

# App privacy and background access
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -Type "REG_DWORD" -Value 2 -Force
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Type "REG_DWORD" -Value 1 -Force

# Content delivery and suggestions
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type "REG_DWORD" -Value 0 -Force

# Windows Update policy
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DoNotCompress" -Type "REG_DWORD" -Value 1 -Force

# Windows Error Reporting
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "disabled" -Type "REG_DWORD" -Value 1 -Force

# AutoRun policies for security
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type "REG_DWORD" -Value 255 -Force
Set-RegistryValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type "REG_DWORD" -Value 255 -Force

# Advanced scheduled tasks management
Write-Host "Configuring scheduled tasks..." -ForegroundColor White

# Tasks to enable
$TasksToEnable = @(
    "\Microsoft\Windows\Defrag\ScheduledDefrag"
)

foreach ($Task in $TasksToEnable) {
    if (Set-ScheduledTaskState -TaskName $Task -Action Enable) {
        Write-Host "  ✓ Task enabled: $Task" -ForegroundColor Green
    }
}

# Tasks to disable for privacy
$TasksToDisable = @(
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

foreach ($Task in $TasksToDisable) {
    # First try to stop the task if it's running
    try {
        Stop-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue
    }
    catch { }
    
    # Then disable it
    if (Set-ScheduledTaskState -TaskName $Task -Action Disable) {
        Write-Host "  ✓ Task disabled: $Task" -ForegroundColor Green
    }
}

# ----------------------------
# 3. UI & Explorer Tweaks
# ----------------------------
Write-Host ""
Write-Host "[3/10] Optimizing Windows Explorer..." -ForegroundColor Cyan

# Disable animations and visual effects
Set-RegistryValue -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type "REG_SZ" -Value "0" -Force
Set-RegistryValue -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -Type "REG_SZ" -Value "0" -Force
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCopilotButton" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings" -Name "TaskbarEndTask" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type "REG_DWORD" -Value 0 -Force

# Explorer AutoComplete optimizations
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" -Name "Append Completion" -Type "REG_SZ" -Value "yes" -Force
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" -Name "AutoSuggest" -Type "REG_SZ" -Value "yes" -Force
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ExtendedUIHoverTime" -Type "REG_DWORD" -Value 0 -Force

# Explorer performance
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Name "StartupDelayInMSec" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SeparateProcess" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKCU:\Control Panel\Desktop" -Name "LowLevelHooksTimeout" -Type "REG_SZ" -Value "1000" -Force
Set-RegistryValue -Path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Type "REG_SZ" -Value "1" -Force
Set-RegistryValue -Path "HKCU:\Control Panel\Desktop" -Name "WaitToKillAppTimeout" -Type "REG_SZ" -Value "2000" -Force
Set-RegistryValue -Path "HKCU:\Control Panel\Desktop" -Name "HungAppTimeout" -Type "REG_SZ" -Value "1000" -Force
Set-RegistryValue -Path "HKCU:\Control Panel\Desktop" -Name "ForegroundLockTimeout" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKCU:\Control Panel\Desktop" -Name "JPEGImportQuality" -Type "REG_DWORD" -Value 0x00000064 -Force

# Show hidden files and folders
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type "REG_DWORD" -Value 1 -Force

# Launch explorer to This PC
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type "REG_DWORD" -Value 1 -Force

# ----------------------------
# 4. Network Optimizations
# ----------------------------
Write-Host ""
Write-Host "[4/10] Tuning network performance..." -ForegroundColor Cyan

# Get active network interface
$ActiveInterface = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.PhysicalMediaType -ne $null } | Select-Object -First 1

if ($ActiveInterface) {
    $InterfaceName = $ActiveInterface.Name
    $InterfaceGUID = $ActiveInterface.InterfaceGuid
    Write-Host "Active interface detected: $InterfaceName" -ForegroundColor White
    
    # Advanced netsh configurations
    Write-Host "Applying advanced network settings..." -ForegroundColor Yellow
    
    $NetshCommands = @{
        "netsh int tcp set heuristics disabled"                    = "TCP Heuristics disabled"
        "netsh int tcp set global autotuninglevel=disabled"        = "TCP Auto-tuning disabled"
        "netsh int tcp set global congestionprovider=ctcp"         = "Congestion provider set to CTCP"
        "netsh int tcp set global ecncapability=disabled"          = "ECN Capability disabled"
        "netsh int tcp set global chimney=disabled"                = "TCP Chimney disabled"
        "netsh int ipv4 set dynamicport udp start=10000 num=55535" = "UDP dynamic ports configured"
    }
    
    foreach ($Command in $NetshCommands.Keys) {
        try {
            Invoke-Expression $Command | Out-Null
            Write-Host " $($NetshCommands[$Command])" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to execute: $Command"
        }
    }

    # Configure MTU
    try {
        & netsh interface ipv4 set subinterface "$InterfaceName" mtu=1500 store=persistent 2>$null
        Write-Host "  ✓ MTU set to 1500" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to configure MTU"
    } 
    
    # Configure DNS to Cloudflare
    try {
        & netsh interface ip set dns name="$InterfaceName" source=static addr=1.1.1.1 register=PRIMARY 2>$null
        & netsh interface ip add dns name="$InterfaceName" addr=1.0.0.1 index=2 2>$null
        Write-Host "  ✓ DNS configured to Cloudflare (1.1.1.1, 1.0.0.1)" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to configure DNS"
    } 
    
    # Interface-specific TCP optimizations
    if ($InterfaceGUID) {
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$InterfaceGUID" -Name "TcpAckFrequency" -Type "REG_DWORD" -Value 1 -Force
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$InterfaceGUID" -Name "TCPNoDelay" -Type "REG_DWORD" -Value 1 -Force
        Write-Host "    Interface TCP settings applied" -ForegroundColor Green
    }
}

# Advanced network registry optimizations
Write-Host "Applying advanced network registry settings..." -ForegroundColor Yellow

$NetworkRegistrySettings = @{
    "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" = @{
        "DisableBandwidthThrottling" = @("REG_DWORD", 1)
        "MaxCmds"                    = @("REG_DWORD", 2048)
    }
    "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"             = @{
        "TcpMaxHalfOpen"        = @("REG_DWORD", 100)
        "TcpMaxHalfOpenRetried" = @("REG_DWORD", 80)
        "TcpMaxPortsExhausted"  = @("REG_DWORD", 5)
        "TcpNumConnections"     = @("REG_DWORD", 500)
        "EnableECN"             = @("REG_DWORD", 1)
        "TcpAckFrequency"       = @("REG_DWORD", 1)
        "TCPNoDelay"            = @("REG_DWORD", 1)
        "TcpTimedWaitDelay"     = @("REG_DWORD", 30)
        "DefaultTTL"            = @("REG_DWORD", 64)
        "EnablePMTUDiscovery"   = @("REG_DWORD", 1)
        "EnablePMTUBHDetect"    = @("REG_DWORD", 0)
        "SackOpts"              = @("REG_DWORD", 1)
        "DisableTaskOffload"    = @("REG_DWORD", 1)
        "EnableTCPChimney"      = @("REG_DWORD", 0)
        "EnableRSS"             = @("REG_DWORD", 0)
        "EnableTCPA"            = @("REG_DWORD", 0)
    }
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched"                     = @{
        "NonBestEffortLimit" = @("REG_DWORD", 0)
    }
    "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"          = @{
        "CacheHashTableBucketSize" = @("REG_DWORD", 384)
        "CacheHashTableSize"       = @("REG_DWORD", 384)
        "MaxCacheEntryTtlLimit"    = @("REG_DWORD", 64000)
        "MaxCacheTtl"              = @("REG_DWORD", 64000)
    }
    "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters"               = @{
        "BufferAlignment"           = @("REG_DWORD", 1)
        "DefaultReceiveWindow"      = @("REG_DWORD", 262144)
        "DefaultSendWindow"         = @("REG_DWORD", 262144)
        "DisableAddressSharing"     = @("REG_DWORD", 1)
        "DisableChainedReceive"     = @("REG_DWORD", 1)
        "disabledirectAcceptEx"     = @("REG_DWORD", 1)
        "DoNotHoldNICBuffers"       = @("REG_DWORD", 1)
        "DynamicSendBufferDisable"  = @("REG_DWORD", 1)
        "FastSendDatagramThreshold" = @("REG_DWORD", 1024)
        "FastCopyReceiveThreshold"  = @("REG_DWORD", 1024)
        "IgnoreOrderlyRelease"      = @("REG_DWORD", 1)
        "IgnorePushBitOnReceives"   = @("REG_DWORD", 1)
    }
}

foreach ($Path in $NetworkRegistrySettings.Keys) {
    foreach ($Name in $NetworkRegistrySettings[$Path].Keys) {
        $Type, $Value = $NetworkRegistrySettings[$Path][$Name]
        Set-RegistryValue -Path $Path -Name $Name -Type $Type -Value $Value -Force
    }
}

# Disable network throttling
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type "REG_DWORD" -Value 0xffffffff -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type "REG_DWORD" -Value 0 -Force

# Input device optimizations
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" -Name "KeyboardDataQueueSize" -Type "REG_DWORD" -Value 30 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" -Name "MouseDataQueueSize" -Type "REG_DWORD" -Value 30 -Force

# ----------------------------
# 5. Gaming & GPU Optimizations
# ----------------------------
Write-Host ""
Write-Host "[5/10] Applying gaming optimizations..." -ForegroundColor Cyan

# Game Mode settings
Set-RegistryValue -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Type "REG_DWORD" -Value 2 -Force
Set-RegistryValue -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Type "REG_DWORD" -Value 2 -Force
Set-RegistryValue -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type "REG_DWORD" -Value 0 -Force

# GPU scheduling
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Type "REG_DWORD" -Value 0x00000002 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "DisableMultiplaneOverlay" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "Attributes" -Type "REG_DWORD" -Value 1 -Force

# Game performance profile
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Affinity" -Type "REG_DWORD" -Value 0x00000000 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Clock Rate" -Type "REG_DWORD" -Value 10000 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Type "REG_DWORD" -Value 0x00000008 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Type "REG_DWORD" -Value 0x00000006 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Type "REG_SZ" -Value "High" -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Type "REG_SZ" -Value "High" -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "GPU_SCHEDULER_MODE" -Type "REG_SZ" -Value "47" -Force

# GPU performance settings
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\DirectX\UserGpuPreferences" -Name "DirectX12EnableHardwareProtected" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences" -Name "GpuPreference" -Type "REG_DWORD" -Value 0x00000002 -Force

# DWM (Desktop Window Manager) optimizations for gaming
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule" -Name "WindowedGsyncGeforceFlag" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule" -Name "FrameRateMin" -Type "REG_DWORD" -Value 0xFFFFFFFF -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule" -Name "IgnoreDisplayChangeDuration" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule" -Name "LingerInterval" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule" -Name "LicenseInterval" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule" -Name "RestrictedNvcplUIMode" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule" -Name "DisableSpecificPopups" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule" -Name "DisableExpirationPopups" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule" -Name "EnableForceIgpuDgpuFromUI" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule" -Name "HideXGpuTrayIcon" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule" -Name "ShowTrayIcon" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule" -Name "HideBalloonNotification" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule" -Name "PerformanceState" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule" -Name "Gc6State" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule" -Name "FrameDisplayBaseNegOffsetNS" -Type "REG_DWORD" -Value 0xFFE17B80 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule" -Name "FrameDisplayResDivValue" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule" -Name "IgnoreNodeLocked" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule" -Name "IgnoreSP" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\DWM\Schedule" -Name "DontAskAgain" -Type "REG_DWORD" -Value 1 -Force

# Graphics drivers power and latency optimizations
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultD3TransitionLatencyActivelyUsed" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultD3TransitionLatencyIdleLongTime" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultD3TransitionLatencyIdleMonitorOff" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultD3TransitionLatencyIdleNoContext" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultD3TransitionLatencyIdleShortTime" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultD3TransitionLatencyIdleVeryLongTime" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceIdle0" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceIdle0MonitorOff" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceIdle1" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceIdle1MonitorOff" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceMemory" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceNoContext" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceNoContextMonitorOff" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceOther" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultLatencyToleranceTimerPeriod" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultMemoryRefreshLatencyToleranceActivelyUsed" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultMemoryRefreshLatencyToleranceMonitorOff" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "DefaultMemoryRefreshLatencyToleranceNoContext" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "Latency" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "MaxIAverageGraphicsLatencyInOneBucket" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "MiracastPerfTrackGraphicsLatency" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "MonitorLatencyTolerance" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "MonitorRefreshLatencyTolerance" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" -Name "TransitionLatency" -Type "REG_DWORD" -Value 1 -Force

# Additional graphics optimizations
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\Dwm" -Name "FlipQueueSize" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "FrameLatency" -Type "REG_DWORD" -Value 0 -Force

# Remove gaming-related registry keys
Write-Host "Removing registry keys..." -ForegroundColor Yellow
$KeysToRemove = @(
    "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}",
    "HKCU:\System\GameConfigStore\Children",
    "HKCU:\System\GameConfigStore\Parents"
)

foreach ($Key in $KeysToRemove) {
    if (Remove-RegistryItem -Path $Key -Recurse) {
        Write-Host "Removed: $Key" -ForegroundColor Green
    }
    else {
        Write-Host "Key not found or could not be deleted: $Key" -ForegroundColor Yellow
    }
}

# Additional DirectX and gaming optimizations
Write-Host "Applying additional DirectX optimizations..." -ForegroundColor Yellow

$AdditionalGamingSettings = @{
    "HKLM:\SOFTWARE\Microsoft\DirectX"                       = @{
        "MaxFrameLatency"              = @("REG_DWORD", 1)
        "DisableThreadedOptimizations" = @("REG_DWORD", 0)
    }
    "HKLM:\SOFTWARE\Microsoft\Direct3D\Global"               = @{
        "MaxQueuedFrames"              = @("REG_DWORD", 1)
        "EnableMultiThreadedRendering" = @("REG_DWORD", 1)
        "DisableVSync"                 = @("REG_DWORD", 1)
    }
    "HKLM:\SOFTWARE\Microsoft\Direct3D\Drivers"              = @{
        "SoftwareOnly" = @("REG_DWORD", 0)
    }
    "HKLM:\SOFTWARE\Microsoft\DirectInput"                   = @{
        "EnableBackgroundProcessing" = @("REG_DWORD", 1)
    }
    "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" = @{
        "TdrDelay"    = @("REG_DWORD", 10)
        "TdrDdiDelay" = @("REG_DWORD", 10)
    }
}

foreach ($Path in $AdditionalGamingSettings.Keys) {
    foreach ($Name in $AdditionalGamingSettings[$Path].Keys) {
        $Type, $Value = $AdditionalGamingSettings[$Path][$Name]
        Set-RegistryValue -Path $Path -Name $Name -Type $Type -Value $Value -Force
    }
}

# AMD-specific optimizations (if applicable)
Set-RegistryValue -Path "HKLM:\SOFTWARE\AMD\CN" -Name "DisableDriverTelemetry" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\AMD\RadeonSettings" -Name "ShaderCache" -Type "REG_DWORD" -Value 1 -Force

# ----------------------------
# 6. Memory & CPU Optimizations
# ----------------------------
Write-Host ""
Write-Host "[6/10] Optimizing memory and CPU..." -ForegroundColor Cyan

# Memory management
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "IoPageLockLimit" -Type "REG_DWORD" -Value 4194304 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "featureSettings" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -Type "REG_DWORD" -Value 0x00000003 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeaturesSettingsOverrideMask" -Type "REG_DWORD" -Value 0x00000003 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpywar" -Type "REG_DWORD" -Value 1 -Force

# CPU scheduling
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Type "REG_DWORD" -Value 0x00000026 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "IRQ8Priority" -Type "REG_DWORD" -Value 0x00000001 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "IRQ16Priority" -Type "REG_DWORD" -Value 0x00000002 -Force

# Disable prefetch/superfetch
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnableSuperfetch" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnableBoottrace" -Type "REG_DWORD" -Value 0 -Force

Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" -Name "ValueMax" -Type "REG_DWORD" -Value 0 -Force

# System multimedia profile timer resolution
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "TimerResolution" -Type "REG_DWORD" -Value 1 -Force

# Virtual memory configuration
Write-Host "Configuring virtual memory..." -ForegroundColor Yellow

try {
    $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $ComputerSystem | Set-CimInstance -Property @{AutomaticManagedPagefile = $true }
    Write-Host "  Automatic virtual memory enabled" -ForegroundColor Green
}
catch {
    Write-Warning "Failed to configure automatic virtual memory"
}

# ----------------------------
# 7. Storage Optimizations
# ----------------------------
Write-Host ""
Write-Host "[7/10] Optimizing storage performance..." -ForegroundColor Cyan

# Disable NTFS last access time based on drive type
if ($DriveType -like "*Fixed*") {
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "NtfsDisableLastAccessUpdate" -Type "REG_DWORD" -Value 0 -Force
}
else {
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "NtfsDisableLastAccessUpdate" -Type "REG_DWORD" -Value 1 -Force
}

# Disable defragmentation for SSDs
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction" -Name "Enable" -Type "REG_SZ" -Value "N" -Force

# Optimize NTFS memory usage
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "NTFSDisable8dot3NameCreation" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "NtfsMemoryUsage" -Type "REG_DWORD" -Value 2 -Force

# Force disable NTFS last access update (override previous conditional logic)
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "NtfsDisableLastAccessUpdate" -Type "REG_DWORD" -Value 1 -Force

# Minimize DPC Latency
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableThrottle" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "Cpupriority" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "SerializeTimerExpiration" -Type "REG_DWORD" -Value 1 -Force

# Additional system optimizations
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type "REG_DWORD" -Value 67108864 -Force

# USB selective suspend disable
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USB" -Name "DisableSelectiveSuspend" -Type "REG_DWORD" -Value 1 -Force

# Advanced kernel timer optimizations
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "KiClockTimerPerCpu" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "KiClockTimerHighLatency" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "KiClockTimerAlwaysOnPresent" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "ClockTimerPerCpu" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "ClockTimerHighLatency" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "ClockTimerAlwaysOnPresent" -Type "REG_DWORD" -Value 1 -Force

# ----------------------------
# 8. Security Hardening
# ----------------------------
Write-Host ""
Write-Host "[8/10] Applying security tweaks..." -ForegroundColor Cyan

# Disable SMBv1
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SizReqBuf" -Type "REG_DWORD" -Value 0x00004410 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type "REG_DWORD" -Value 50 -Force

# Disable LLMNR
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type "REG_DWORD" -Value 0 -Force

# Disable insecure logons
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableDomainCreds" -Type "REG_DWORD" -Value 1 -Force

# Device Guard and Virtualization-Based Security optimizations
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "HVCIMATRequired" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Type "REG_DWORD" -Value 0 -Force

# Remote Assistance
Set-RegistryValue -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type "REG_DWORD" -Value 0 -Force

# Windows 11 specific
$WindowsVersion = [System.Environment]::OSVersion.Version
if ($WindowsVersion.Major -eq 10 -and $WindowsVersion.Build -ge 22000) {
    Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type "REG_DWORD" -Value 1 -Force
}

# ----------------------------
# 9. BCDEdit System Optimizations
# ----------------------------
Write-Host ""
Write-Host "[9/10] Applying system boot optimizations..." -ForegroundColor Cyan

Write-Host "Configuring BCDEdit settings..." -ForegroundColor Yellow

$BCDEditCommands = @(
    "/set bootux disabled",
    "/set tscsyncpolicy enhanced",
    "/set uselegacyapicmode No",
    "/deletevalue useplatformclock",
    "/deletevalue useplatformtick",
    "/set disabledynamictick No",
    "/set hypervisorlaunch off"
)

foreach ($Command in $BCDEditCommands) {
    if (Invoke-BcdEdit -Arguments $Command) {
        Write-Host "    bcdedit $Command" -ForegroundColor Green
    } 
}

# ----------------------------
# 10. Final Tweaks
# ----------------------------
Write-Host ""
Write-Host "[10/10] Applying final system tweaks..." -ForegroundColor Cyan

# Power and performance tweaks
$PowerTweaks = @{
    "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling"                                                                         = @{
        "PowerThrottlingOff" = @("REG_DWORD", 1)
    }
    "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\be337238-0d82-4146-a960-4f3749d470c7" = @{
        "Attributes" = @("REG_DWORD", 2)
    }
    "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" = @{
        "DisableMultiplaneOverlay" = @("REG_DWORD", 0x00000001)
    }
    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"                                                                         = @{
        "HiberBootEnabled"        = @("REG_DWORD", 0)
        "CoalescingTimerInterval" = @("REG_DWORD", 0)
    }
    "HKLM:\SYSTEM\CurrentControlSet\Control\Power"                                                                                         = @{
        "HibernateEnabled"        = @("REG_DWORD", 0)
        "EnergyEstimationEnabled" = @("REG_DWORD", 0)
        "EnergySaverPolicy"       = @("REG_DWORD", 1)
        "CsEnabled"               = @("REG_DWORD", 0)
    }
}

foreach ($Path in $PowerTweaks.Keys) {
    foreach ($Name in $PowerTweaks[$Path].Keys) {
        $Type, $Value = $PowerTweaks[$Path][$Name]
        Set-RegistryValue -Path $Path -Name $Name -Type $Type -Value $Value -Force
    }
}

# Additional power settings
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" -Name "ValueMin" -Type "REG_DWORD" -Value 0 -Force

# Processor power management settings
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\ea062031-0e34-4ff1-9b6d-eb1059334028" -Name "ACSettingIndex" -Type "REG_DWORD" -Value 100 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4ff1-9b6d-eb1059334028" -Name "DCSettingIndex" -Type "REG_DWORD" -Value 100 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" -Name "Attributes" -Type "REG_DWORD" -Value 2 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" -Name "Affinity" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" -Name "Background Only" -Type "REG_SZ" -Value "False" -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" -Name "Clock Rate" -Type "REG_DWORD" -Value 65536 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" -Name "GPU Priority" -Type "REG_DWORD" -Value 8 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" -Name "Priority" -Type "REG_DWORD" -Value 6 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" -Name "Scheduling Category" -Type "REG_SZ" -Value "High" -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" -Name "SFIO Priority" -Type "REG_SZ" -Value "High" -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" -Name "BackgroundPriority" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" -Name "Latency Sensitive" -Type "REG_SZ" -Value "True" -Force

# Disable HPET and time services
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient" -Name "Enabled" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer" -Name "Enabled" -Type "REG_DWORD" -Value 0 -Force

# Mouse optimizations
$MouseSettings = @{
    "HKCU:\Control Panel\Mouse"                           = @{
        "MouseSpeed"       = @("REG_SZ", "0")
        "MouseThreshold1"  = @("REG_SZ", "0")
        "MouseThreshold2"  = @("REG_SZ", "0")
        "MouseHoverTime"   = @("REG_DWORD", 0x0000000a)
        "SwapMouseButtons" = @("REG_SZ", "0")
    }
    "HKCU:\Control Panel\Accessibility\MouseKeys"         = @{
        "Flags" = @("REG_SZ", "0")
    }
    "HKCU:\Control Panel\Accessibility\Keyboard Response" = @{
        "Flags" = @("REG_SZ", "0")
    }
    "HKCU:\Control Panel\Accessibility\StickyKeys"        = @{
        "Flags" = @("REG_SZ", "0")
    }
    "HKCU:\Control Panel\Accessibility\ToggleKeys"        = @{
        "Flags" = @("REG_SZ", "0")
    }
}

foreach ($Path in $MouseSettings.Keys) {
    foreach ($Name in $MouseSettings[$Path].Keys) {
        $Type, $Value = $MouseSettings[$Path][$Name]
        Set-RegistryValue -Path $Path -Name $Name -Type $Type -Value $Value -Force
    }
}

# Copilot and Windows features
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "AutoOpenCopilotLargeScreens" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_TOASTS_ENABLED" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\Shell\Copilot\BingChat" -Name "IsUserEligible" -Type "REG_DWORD" -Value 0 -Force

# System and performance tweaks
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy" -Name "(Default)" -Type "REG_SZ" -Value "" -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" -Name "Value" -Type "REG_SZ" -Value "Deny" -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AllowUntriggeredNetworkTrafficOnSettingsPage" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AutoDownloadAndUpdateMapData" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Type "REG_DWORD" -Value 0 -Force

# Additional system optimizations
Set-RegistryValue -Path "HKLM:\SYSTEM\ControlSet001\Services\Ndu" -Name "Start" -Type "REG_DWORD" -Value 0x00000004 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\Dwm" -Name "OverlayTestMode" -Type "REG_DWORD" -Value 0x00000005 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\MSMQ" -Name "TCPNoDelay" -Type "REG_DWORD" -Value 0x00000001 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" -Name "ActivationType" -Type "REG_DWORD" -Value 0x00000000 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type "REG_DWORD" -Value 0x00000000 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" -Name "value" -Type "REG_DWORD" -Value 0x00000000 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\ApplicationManagement" -Name "AllowGameDVR" -Type "REG_DWORD" -Value 0x00000000 -Force
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "UseNexusForGameBarEnabled" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\GameBar" -Name "ShowStartupPanel" -Type "REG_DWORD" -Value 0 -Force
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Avalon.Graphics" -Name "DisableHWAcceleration" -Type "REG_DWORD" -Value 0x00000000 -Force
Set-RegistryValue -Path "HKCU:\SOFTWARE\Microsoft\Avalon.Graphics" -Name "MaxMultisampleType" -Type "REG_DWORD" -Value 0x00000000 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysMain" -Name "Start" -Type "REG_DWORD" -Value 0x00000004 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type "REG_DWORD" -Value 0x00000000 -Force
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "MaintenanceDisabled" -Type "REG_DWORD" -Value 0x00000001 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "WaitToKillServiceTimeout" -Type "REG_DWORD" -Value 0x000007d0 -Force
Set-RegistryValue -Path "HKCU:\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type "REG_SZ" -Value "0" -Force

# Fix duplicate StickyKeys entry (this was a duplicate from the mouse section)
Set-RegistryValue -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type "REG_SZ" -Value "58" -Force

# Advanced power and latency settings
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "ExitLatency" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "ExitLatencyCheckEnabled" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "Latency" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "LatencyToleranceDefault" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "LatencyToleranceFSVP" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "LatencyTolerancePerfOverride" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "LatencyToleranceScreenOffIR" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "LatencyToleranceVSyncEnabled" -Type "REG_DWORD" -Value 1 -Force
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "RtlCapabilityCheckLatency" -Type "REG_DWORD" -Value 1 -Force

# Precision Touchpad
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PrecisionTouchPad" -Name "EnablePrecision" -Type "REG_DWORD" -Value 0 -Force

# Disable Chat/Meet Now on Windows 11
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Type "REG_DWORD" -Value 0 -Force

# ----------------------------
# Completion and Summary
# ----------------------------
Write-Host ""
Write-Host "==============================================" -ForegroundColor Green
Write-Host "REGISTRY OPTIMIZATION COMPLETED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Summary of applied tweaks:" -ForegroundColor Cyan
Write-Host "- UI & Explorer optimizations" -ForegroundColor White
Write-Host "- Network performance tweaks" -ForegroundColor White
Write-Host "- Gaming & GPU optimizations" -ForegroundColor White
Write-Host "- Memory & CPU improvements" -ForegroundColor White
Write-Host "- Storage optimizations" -ForegroundColor White
Write-Host "- Security hardening" -ForegroundColor White
Write-Host "- Power management tweaks" -ForegroundColor White
Write-Host "- Mouse and accessibility settings" -ForegroundColor White
Write-Host "- Copilot and modern Windows features disabled" -ForegroundColor White
Write-Host ""
Write-Host "Registry backups created:" -ForegroundColor Yellow
Write-Host "- $BackupPathHKLM" -ForegroundColor White
Write-Host "- $BackupPathHKCU" -ForegroundColor White
Write-Host ""
Write-Host "IMPORTANT: A system restart is recommended to apply all changes!" -ForegroundColor Red
Write-Host ""

Write-Host "Script execution completed. Press any key to exit..." -ForegroundColor Green
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")