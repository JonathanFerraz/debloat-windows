@echo off
:: ==============================================
:: Windows Registry Optimization Script
:: Version: 4.0 | Date: 2025-04-27
:: ==============================================
:: Description:
:: This script applies extreme performance tweaks,
:: privacy settings and system optimizations
:: through Windows Registry modifications
:: ==============================================

:: ----------------------------
:: Initial Setup
:: ----------------------------
setlocal EnableDelayedExpansion
title Windows Registry Optimizer v4.0
color 0a
echo.
echo ==============================================
echo APPLYING ULTIMATE PERFORMANCE REGISTRY TWEAKS
echo ==============================================

echo Criando backup do registro...
reg export HKLM "C:\RegBackup_HKLM_%date:~-4,4%%date:~-10,2%%date:~-7,2%.reg" /y
reg export HKCU "C:\RegBackup_HKCU_%date:~-4,4%%date:~-10,2%%date:~-7,2%.reg" /y

:: ----------------------------
:: 1. System Information
:: ----------------------------
echo.
echo [1/9] Gathering system information...
for /f "tokens=2 delims==" %%a in ('wmic os get caption /value') do set "OS=%%a"
for /f "tokens=2 delims==" %%a in ('wmic computersystem get model /value') do set "MODEL=%%a"
echo Detected: !OS! on !MODEL!

:: ----------------------------
:: 2. Privacy & Telemetry
:: ----------------------------
echo.
echo [2/9] Applying privacy settings...



:: ----------------------------
:: 3. UI & Explorer Tweaks
:: ----------------------------
echo.
echo [3/9] Optimizing Windows Explorer...

:: Disable animations and visual effects
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_SZ /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCopilotButton" /t "REG_DWORD" /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings" /v "TaskbarEndTask" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
@REM reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d 0 /f
@REM reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d 0 /f

:: Explorer performance
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SeparateProcess" /t REG_DWORD /d 0 /f

:: Lanch explorer to This PC
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "0x00000001" /f

:: ----------------------------
:: 4. Network Optimizations
:: ----------------------------
echo.
echo [4/9] Tuning network performance...

:: TCP/IP optimizations
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpAckFrequency" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPNoDelay" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d 30 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d 64 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUBHDetect" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d 0 /f

:: Disable network throttling
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 0xffffffff /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0x0000000a" /f

:: ----------------------------
:: 5. Gaming & GPU Optimizations
:: ----------------------------
echo.
echo [5/9] Applying gaming optimizations...

:: Game Mode settings
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d 2 /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d 1 /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f

:: GPU scheduling
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DisableMultiplaneOverlay" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "Attributes" /t REG_DWORD /d 1 /f

:: Game performance profile
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0x00000000" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "0x00000008" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "0x00000006" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "GPU_SCHEDULER_MODE" /t REG_SZ /d "47" /f

:: Força modo de alto desempenho em GPUs NVIDIA/AMD
reg add "HKLM\SOFTWARE\Microsoft\DirectX\UserGpuPreferences" /v "DirectX12EnableHardwareProtected" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\DirectX\UserGpuPreferences" /v "GpuPreference" /t REG_DWORD /d "0x00000002" /f

:: Remove registry keys
echo Removing registry keys...
reg delete "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" /f 2>nul
if not %errorlevel% == 0 echo Key not found or could not be deleted.

reg delete "HKCU\System\GameConfigStore\Children" /f 2>nul
if not %errorlevel% == 0 echo Key not found or could not be deleted.

reg delete "HKCU\System\GameConfigStore\Parents" /f 2>nul
if not %errorlevel% == 0 echo Key not found or could not be deleted.

:: ----------------------------
:: 6. Memory & CPU Optimizations
:: ----------------------------
echo.
echo [6/9] Optimizing memory and CPU...

:: Memory management
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d 4194304 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "featureSettings" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "0x00000003" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeaturesSettingsOverrideMask" /t REG_DWORD /d "0x00000003" /f

:: CPU scheduling
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "0x0000001a" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d "0x00000002" /f

:: Disable prefetch/superfetch
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableBoottrace" /t REG_DWORD /d 0 /f

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f

:: ----------------------------
:: 7. Storage Optimizations
:: ----------------------------
echo.
echo [7/9] Optimizing storage performance...

:: Disable NTFS last access time
@REM reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisableLastAccessUpdate" /t REG_DWORD /d 1 /f
for /f "tokens=2 delims==" %%a in ('wmic diskdrive get MediaType /value ^| find "MediaType"') do set "DRIVETYPE=%%a"
if "!DRIVETYPE!"=="Fixed hard disk media" (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisableLastAccessUpdate" /t REG_DWORD /d 0 /f
)

:: Disable defragmentation for SSDs
reg add "HKLM\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction" /v "Enable" /t REG_SZ /d "N" /f

:: Optimize NTFS memory usage
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisable8dot3NameCreation" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMemoryUsage" /t REG_DWORD /d 2 /f

:: Minimiza DPC Latency (reduz atrasos)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableThrottle" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "Cpupriority" /t REG_DWORD /d 1 /f

:: ----------------------------
:: 8. Security Hardening
:: ----------------------------
echo.
echo [8/9] Applying security tweaks...

:: Disable SMBv1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "0x00004410" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "50" /f

:: Disable LLMNR
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d 0 /f

:: Disable insecure logons
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableDomainCreds" /t REG_DWORD /d 1 /f

ver | find "11." > nul
if %errorlevel% equ 0 (
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAMeetNow" /t REG_DWORD /d 1 /f
)

:: ----------------------------
:: 9. Final Tweaks
:: ----------------------------
echo.
echo [9/9] Applying final system tweaks...

:: Disable power throttling
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\be337238-0d82-4146-a960-4f3749d470c7" /v Attributes /t REG_DWORD /d 2 /f >nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "DisableMultiplaneOverlay" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberBootEnabled /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v HibernateEnabled /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergySaverPolicy" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CsEnabled" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" /v "Attributes" /t REG_DWORD /d 2 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" /v "Affinity" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" /v "Background Only" /t REG_SZ /d "False" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" /v "Clock Rate" /t REG_DWORD /d 65536 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" /v "GPU Priority" /t REG_DWORD /d 8 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" /v "Priority" /t REG_DWORD /d 6 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" /v "Scheduling Category" /t REG_SZ /d "High" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" /v "SFIO Priority" /t REG_SZ /d "High" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" /v "BackgroundPriority" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" /v "Latency Sensitive" /t REG_SZ /d "True" /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d 0 /f >nul

:: Disable HPET (for low-latency systems)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer" /v "Enabled" /t REG_DWORD /d 0 /f

:: Disable mouse acceleration
reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_DWORD /d "0x0000000a" /f
reg add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "0" /f

:: Others
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /v "TurnOffWindowsCopilot" /t "REG_DWORD" /d "1" /f
reg add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /v "TurnOffWindowsCopilot" /t "REG_DWORD" /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "AutoOpenCopilotLargeScreens" /t "REG_DWORD" /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_TOASTS_ENABLED" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\Shell\Copilot\BingChat" /v "IsUserEligible" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "HubsSidebarEnabled" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /d "0" /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /d "Deny" /t REG_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AllowUntriggeredNetworkTrafficOnSettingsPage" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v "01" /t REG_DWORD /d 0 /f

reg add "HKLM\SYSTEM\ControlSet001\Services\Ndu" /v "Start" /t REG_DWORD /d "0x00000004" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "OverlayTestMode" /t REG_DWORD /d "0x00000005" /f
reg add "HKLM\SOFTWARE\Microsoft\MSMQ" /v "TCPNoDelay" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" /v "ActivationType" /t REG_DWORD /d "0x00000000" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0x00000000" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d "0x00000000" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\ApplicationManagement" /v "AllowGameDVR" /t REG_DWORD /d "0x00000000" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Avalon.Graphics" /v "DisableHWAcceleration" /t REG_DWORD /d "0x00000000" /f
reg add "HKCU\SOFTWARE\Microsoft\Avalon.Graphics" /v "MaxMultisampleType" /t REG_DWORD /d "0x00000000" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SysMain" /v "Start" /t REG_DWORD /d "0x00000004" /f
reg add "HKLM\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "0x02000000" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0x00000000" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_DWORD /d "0x00000bb8" /f
reg add "HKCU\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "58" /f

::
::
:: NOVOS PARA TESTE AINDA EM APRIMORAMENTO
::
::

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsRunInBackground /t REG_DWORD /d 2 /f >nul 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f >nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v disabled /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f >nul
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f >nul

reg add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v KeyboardDataQueueSize /t REG_DWORD /d 30 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v MouseDataQueueSize /t REG_DWORD /d 30 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v SerializeTimerExpiration /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v SvcHostSplitThresholdInKB /t REG_DWORD /d 33554432 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisableLastAccessUpdate" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\USB" /v "DisableSelectiveSuspend" /t REG_DWORD /d 1 /f >nul 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d 1 /f >nul 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 /f >nul 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f >nul 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d 0 /f >nul 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338393Enabled /t REG_DWORD /d 0 /f >nul
echo  %p%[ %roxo%•%p% %p%]%w% General System Optimizations Applied. %p%(%roxo%27%p%)%w%

bcdedit /set bootux disabled >nul
bcdedit /set tscsyncpolicy enhanced >nul
bcdedit /set uselegacyapicmode No >nul
bcdedit /deletevalue useplatformclock >nul
bcdedit /deletevalue useplatformtick >nul
echo  %p%[ %roxo%•%p% %p%]%w% Advanced System Optimizations %p%(%roxo%Boot%p%)%w% Applied. %p%(%roxo%5%p%)%w%

wmic computersystem >nul 2>&1
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=True >nul 2>&1
sc config SysMain start= disabled >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Defrag\ScheduledDefrag" /ENABLE >nul 2>&1
echo  %p%[ %roxo%•%p% %p%]%w% Optimized Memory %p%(%roxo%RAM%p%)%w% Management. %p%(%roxo%4%p%)%w%


reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "GPU Priority" /t REG_DWORD /d 15 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Priority" /t REG_DWORD /d 8 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Scheduling Category" /t REG_SZ /d "Medium" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "SFIO Priority" /t REG_SZ /d "High" /f >nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 36 /f >nul
reg add "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d 1 /f >nul
reg add "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d 1 /f >nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Games" /v "Start" /t REG_DWORD /d 3 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 26 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "OverlayTestMode" /t REG_DWORD /d 5 /f >nul
echo  %p%[ %roxo%•%p% %p%]%w% Gaming Optimizations Applied. %p%(%roxo%24%p%)%w%

reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d 2 /f >nul 2>&1
reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d 2 /f >nul 2>&1
reg add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d 0 /f >nul 2>&1
echo  %p%[ %roxo%•%p% %p%]%w% Fullscreen Optimizations disabled. %p%(%roxo%3%p%)%w%

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\ea062031-0e34-4ff1-9b6d-eb1059334028" /v ACSettingIndex /t REG_DWORD /d 100 /f >nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4ff1-9b6d-eb1059334028" /v DCSettingIndex /t REG_DWORD /d 100 /f >nul 2>nul

echo  %p%[ %roxo%•%p% %p%]%w% Unpaked all CPU Cores %p%(%roxo%Current Powerplan%p%)%w%. %p%(%roxo%3%p%)%w%

reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v WindowedGsyncGeforceFlag /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v FrameRateMin /t REG_DWORD /d 0xFFFFFFFF /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v IgnoreDisplayChangeDuration /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v LingerInterval /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v LicenseInterval /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v RestrictedNvcplUIMode /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v DisableSpecificPopups /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v DisableExpirationPopups /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v EnableForceIgpuDgpuFromUI /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v HideXGpuTrayIcon /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v ShowTrayIcon /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v HideBalloonNotification /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v PerformanceState /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v Gc6State /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v FrameDisplayBaseNegOffsetNS /t REG_DWORD /d 0xFFE17B80 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v FrameDisplayResDivValue /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v IgnoreNodeLocked /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v IgnoreSP /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\DWM\Schedule" /v DontAskAgain /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem" /v NtfsDisableLastAccessUpdate /t REG_DWORD /d 1 /f >nul 2>&1
echo  %p%[ %roxo%•%p% %p%]%w% DWM Optimizations Applied. %p%(%roxo%20%p%)%w%

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v KiClockTimerPerCpu /t REG_DWORD /d 1 /f >nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v KiClockTimerHighLatency /t REG_DWORD /d 0 /f >nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v KiClockTimerAlwaysOnPresent /t REG_DWORD /d 1 /f >nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v ClockTimerPerCpu /t REG_DWORD /d 1 /f >nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v ClockTimerHighLatency /t REG_DWORD /d 0 /f >nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v ClockTimerAlwaysOnPresent /t REG_DWORD /d 1 /f >nul
bcdedit /set disabledynamictick No >nul
echo  %p%[ %roxo%•%p% %p%]%w% Kernel Optimizations Applied. %p%(%roxo%7%p%)%w%

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f >nul 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v RequirePlatformSecurityFeatures /t REG_DWORD /d 0 /f >nul 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v HVCIMATRequired /t REG_DWORD /d 0 /f >nul 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f >nul 2>nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f >nul 2>nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f >nul 2>nul
bcdedit /set hypervisorlaunch off >nul 2>nul
echo  %p%[ %roxo%•%p% %p%]%w% Virtualization Based Security %p%(%roxo%VBS%p%)%w% disabled. %p%(%roxo%7%p%)%w%

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "RtlCapabilityCheckLatency" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyActivelyUsed" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleLongTime" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleMonitorOff" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleNoContext" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleShortTime" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleVeryLongTime" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0MonitorOff" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1MonitorOff" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceMemory" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContext" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContextMonitorOff" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceOther" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceTimerPeriod" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceActivelyUsed" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceMonitorOff" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceNoContext" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "Latency" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MaxIAverageGraphicsLatencyInOneBucket" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MiracastPerfTrackGraphicsLatency" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorLatencyTolerance" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "TransitionLatency" /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" /v "Append Completion" /t REG_SZ /d "yes" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" /v "AutoSuggest" /t REG_SZ /d "yes" /f >nul
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d 10 /f >nul
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ExtendedUIHoverTime /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "10" /f >nul
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v MouseHoverTime /t REG_SZ /d 10 /f >nul
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v LowLevelHooksTimeout /t REG_SZ /d 1000 /f >nul
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v AutoEndTasks /t REG_SZ /d 1 /f >nul
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v WaitToKillAppTimeout /t REG_SZ /d 2000 /f >nul
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v HungAppTimeout /t REG_SZ /d 1000 /f >nul
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ForegroundLockTimeout /t REG_DWORD /d 0 /f >nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v WaitToKillServiceTimeout /t REG_SZ /d 2000 /f >nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "TimerResolution" /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f >nul
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f >nul
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f >nul
reg add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f >nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Dwm" /v "FlipQueueSize" /t REG_DWORD /d 0 /f >nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v FrameLatency /t REG_DWORD /d 0 /f >nul
echo  %p%[ %roxo%•%p% %p%]%w% Reduced system response time and latency. %p%(%roxo%54%p%)%w%

reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f >nul
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f >nul
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f >nul
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "SwapMouseButtons" /t REG_SZ /d "0" /f >nul
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\PrecisionTouchPad" /v "EnablePrecision" /t REG_DWORD /d 0 /f >nul
echo  %p%[ %roxo%•%p% %p%]%w% Mouse and Touchpad Optimizations Applied. %p%(%roxo%5%p%)%w%

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDa /t REG_DWORD /d 0 /f >nul 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDa /t REG_DWORD /d 0 /f >nul 2>nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarMn /t REG_DWORD /d 0 /f >nul 2>nul
echo  %p%[ %roxo%•%p% %p%]%w% Windows Widgets %p%(%roxo%TaskbarDa/Mn%p%)%w% disabled. %p%(%roxo%3%p%)%w%

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectX" /v "MaxFrameLatency" /t REG_DWORD /d 1 /f >nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D\Global" /v "MaxQueuedFrames" /t REG_DWORD /d 1 /f >nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d 1 /f >nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDelay" /t REG_DWORD /d 10 /f >nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDdiDelay" /t REG_DWORD /d 10 /f >nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectX" /v "DisableThreadedOptimizations" /t REG_DWORD /d 0 /f >nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D\Global" /v EnableMultiThreadedRendering /t REG_DWORD /d 1 /f >nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D\Global" /v DisableVSync /t REG_DWORD /d 1 /f >nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D\Drivers" /v SoftwareOnly /t REG_DWORD /d 0 /f >nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectInput" /v EnableBackgroundProcessing /t REG_DWORD /d 1 /f >nul
echo  %p%[ %roxo%•%p% %p%]%w% Optimized %bb%DirectX%w% rendering. %p%(%roxo%10%p%)%w%

sc stop AMDExternalEvents >nul 2>&1
sc config AMDExternalEvents start= disabled >nul 2>&1
sc stop AMDLinkAgent >nul 2>&1
sc config AMDLinkAgent start= disabled >nul 2>&1
sc stop AMDCrashDefender >nul 2>&1
sc config AMDCrashDefender start= disabled >nul 2>&1
reg add "HKLM\SOFTWARE\AMD\CN" /v "DisableDriverTelemetry" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\AMD\RadeonSettings" /v ShaderCache /t REG_DWORD /d 1 /f >nul 2>&1
echo  %p%[ %roxo%•%p% %p%]%w% %r%AMD%w% Driver Optimizations Applied. %p%(%roxo%8%p%)%w%

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Intel\Display" /v "EnableGameMode" /t REG_DWORD /d 1 /f >nul 2>&1
sc stop "Intel Capability Licensing Service Interface" >nul 2>&1
sc config "Intel Capability Licensing Service Interface" start= disabled >nul 2>&1
sc stop "Intel Dynamic Application Loader Host Interface Service" >nul 2>&1
sc config "Intel Dynamic Application Loader Host Interface Service" start= disabled >nul 2>&1
sc stop "Intel Service Manager" >nul 2>&1
sc config "Intel Service Manager" start= disabled >nul 2>&1
echo  %p%[ %roxo%•%p% %p%]%w% %b%Intel%w% Driver Optimizations Applied. %p%(%roxo%7%p%)%w%

sc stop LMS >nul 2>&1
sc config LMS start= disabled >nul 2>&1
sc stop NvTelemetryContainer >nul 2>&1
sc config NvTelemetryContainer start= disabled >nul 2>&1
sc stop NvTelemetryNetworkService >nul 2>&1
sc config NvTelemetryNetworkService start= disabled >nul 2>&1
sc stop NvTelemetryContainer >nul 2>&1
sc config NvTelemetryContainer start= disabled >nul 2>&1
sc stop NvContainerLocalSystem >nul 2>&1
sc config NvContainerLocalSystem start= disabled >nul 2>&1
sc stop NvContainerNetworkService >nul 2>&1
sc config NvContainerNetworkService start= disabled >nul 2>&1
echo  %p%[ %roxo%•%p% %p%]%w% %g%NVIDIA%w% Driver Optimizations Applied. %p%(%roxo%12%p%)%w%

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f >nul
echo  %p%[ %roxo%•%p% %p%]%w% Advertising with Ad ID disabled... %p%(%roxo%1%p%)%w%

sc stop DiagTrack >nul 2>&1
sc config DiagTrack start= disabled >nul 2>&1
sc stop dmwappushservice >nul 2>&1
sc config dmwappushservice start= disabled >nul 2>&1
sc stop DPS >nul 2>&1
sc config DPS start=disabled >nul 2>&1
sc stop diagnosticshub.standardcollector.service >nul 2>&1
sc config diagnosticshub.standardcollector.service start=disabled >nul 2>&1
echo  %p%[ %roxo%•%p% %p%]%w% Tracking and Telemetry Services disabled... %p%(%roxo%4%p%)%w%

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f >nul
schtasks /change /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable >nul
schtasks /change /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable >nul
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable >nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f >nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack" /v Start /t REG_DWORD /d 4 /f >nul
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable >nul 2>&1
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable >nul 2>&1
echo  %p%[ %roxo%•%p% %p%]%w% Telemetry and Diagnostics disabled... %p%(%roxo%7%p%)%w%

reg add "HKCU\Software\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v PeriodInDays /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v NumberOfNotificationsSent /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f >nul
echo  %p%[ %roxo%•%p% %p%]%w% Personalized %o%Feedback and Experiences%o% disabled... %p%(%roxo%5%p%)%w%

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v Value /t REG_SZ /d Deny /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v Value /t REG_SZ /d Deny /f >nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d 1 /f >nul
echo  %p%[ %roxo%•%p% %p%]%w% Location and Data Sensors %p%(%roxo%Webcam%p%)%w% disabled... %p%(%roxo%4%p%)%w%

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f >nul
echo  %p%[ %roxo%•%p% %p%]%w% Windows Consumer Features %p%(%roxo%Bloatware%p%)%w% disabled... %p%(%roxo%1%p%)%w%

reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f >nul
echo  %p%[ %roxo%•%p% %p%]%w% Online Search on Start Menu disabled... %p%(%roxo%1%p%)%w%

reg add "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f >nul
echo  %p%[ %roxo%•%p% %p%]%w% Remote Assistance disabled. %p%(%roxo%1%p%)%w%

schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable >nul 2>&1
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable >nul 2>&1
echo  %p%[ %roxo%•%p% %p%]%w% Customer Experience Improvement Program collection disabled. %p%(%roxo%10%p%)%w%

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f >nul
echo  %p%[ %roxo%•%p% %p%]%w% Upload Activities %p%(%roxo%Windows Timeline%p%)%w% disabled. %p%(%roxo%2%p%)%w%

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\NVIDIA Corporation\Global\NvTelemetry" /v "Enabled" /t REG_DWORD /d 0 /f >nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\AMD\ACE\Settings\General" /v "EnableTelemetry" /t REG_DWORD /d 0 /f >nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Intel\Display\igfxcui\Telemetry" /v "EnableTelemetry" /t REG_DWORD /d 0 /f >nul
echo  %p%[ %roxo%•%p% %p%]%w% %r%AMD%w%, %b%Intel%w% and %g%NVIDIA%w% Driver telemetry disabled. %p%(%roxo%3%p%)%w%

echo  %p%[ %roxo%•%p% %p%]%w% Blocking telemetry domains... %p%(%roxo%11%p%)%w%
(
echo 0.0.0.0 vortex.data.microsoft.com
echo 0.0.0.0 settings-win.data.microsoft.com
echo 0.0.0.0 watson.telemetry.microsoft.com
echo 0.0.0.0 telemetry.microsoft.com
echo 0.0.0.0 telecommand.telemetry.microsoft.com
echo 0.0.0.0 services.wes.df.telemetry.microsoft.com
echo 0.0.0.0 sqm.df.telemetry.microsoft.com
echo 0.0.0.0 telemetry.nvidia.com
echo 0.0.0.0 telemetry.amd.com
) >> %WINDIR%\System32\drivers\etc\hosts

echo.
echo  %p%[ %roxo%•%p% %p%]%w% Starting %roxo%Network Optimization%w%... %p%(%roxo%~3s%p%)%w%
echo.
timeout /t 2 /nobreak >nul

echo  %p%[ %roxo%•%p% %p%]%w% Detecting Active Network Interface... %p%(%roxo%~2s%p%)%w%
for /f "tokens=3 delims={}" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" ^| find "{"') do (
    set "InterfaceID=%%A"
)

for /f "tokens=1*" %%i in ('netsh interface show interface ^| findstr "Conectado"') do set "netinterface=%%j"

echo  %p%[ %roxo%•%p% %p%]%w% Network Interface detected. %InterfaceID%
timeout /t 1 >nul

netsh int tcp set heuristics disabled >nul
netsh int tcp set global autotuninglevel=disabled >nul
netsh int tcp set global congestionprovider=ctcp >nul
netsh int tcp set global ecncapability=disabled >nul
netsh int tcp set global chimney=disabled >nul
netsh int ipv4 set dynamicport udp start=10000 num=55535 >nul
netsh interface ipv4 set subinterface "%netinterface%" mtu=1500 store=persistent >nul 2>&1
echo  %p%[ %roxo%•%p% %p%]%w% General Network %p%(%roxo%ipv4%p%)%w% Optimizations Applied. %p%(%roxo%7%p%)%w%

netsh interface ip set dns name="%netinterface%" source=static addr=1.1.1.1 register=PRIMARY >nul
netsh interface ip add dns name="%netinterface%" addr=1.0.0.1 index=2 >nul
echo  %p%[ %roxo%•%p% %p%]%w% %o%Cloudflare DNS%w% addresses configured. %p%(%roxo%2%p%)%w%

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 4294967295 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0 /f >nul
echo  %p%[ %roxo%•%p% %p%]%w% Network Throttling disabled. %p%(%roxo%2%p%)%w%

reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{%InterfaceID%}" /v TcpAckFrequency /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{%InterfaceID%}" /v TCPNoDelay /t REG_DWORD /d 1 /f >nul
echo  %p%[ %roxo%•%p% %p%]%w% Nagle Algorithm %p%(%roxo%TCP%p%)%w% disabled. %p%(%roxo%2%p%)%w%

reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableTaskOffload /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableTCPChimney /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableRSS /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableTCPA /t REG_DWORD /d 0 /f >nul
echo  %p%[ %roxo%•%p% %p%]%w% TCP Offload, RSS and NetDMA disabled. %p%(%roxo%4%p%)%w%

reg add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v TCPNoDelay /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v DisableBandwidthThrottling /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v MaxCmds /t REG_DWORD /d 2048 /f >nul
echo  %p%[ %roxo%•%p% %p%]%w% Network Throughput optimizations applied. %p%(%roxo%3%p%)%w%

reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxHalfOpen /t REG_DWORD /d 100 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxHalfOpenRetried /t REG_DWORD /d 80 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxPortsExhausted /t REG_DWORD /d 5 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpNumConnections /t REG_DWORD /d 500 /f >nul
echo  %p%[ %roxo%•%p% %p%]%w% Increased TCP Simultaneous Packets. %p%(%roxo%4%p%)%w%

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v NonBestEffortLimit /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableECN /t REG_DWORD /d 1 /f >nul
echo  %p%[ %roxo%•%p% %p%]%w% Quality of Service %p%(%roxo%QoS%p%)%w% optimizations applied. %p%(%roxo%2%p%)%w%

reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v CacheHashTableBucketSize /t REG_DWORD /d 384 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v CacheHashTableSize /t REG_DWORD /d 384 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v MaxCacheEntryTtlLimit /t REG_DWORD /d 64000 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v MaxCacheTtl /t REG_DWORD /d 64000 /f >nul
echo  %p%[ %roxo%•%p% %p%]%w% DNS Cache optimizations applied. %p%(%roxo%4%p%)%w%

echo  %p%[ %roxo%•%p% %p%]%w% Clearing DNS Cache %p%(%roxo%Flush DNS%p%)%w%...
ipconfig /flushdns >nul
echo  %p%[ %roxo%•%p% %p%]%w% DNS Cache cleared. %p%(%roxo%1%p%)%w%

reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v BufferAlignment /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v DefaultReceiveWindow /t REG_DWORD /d 262144 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v DefaultSendWindow /t REG_DWORD /d 262144 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v DisableAddressSharing /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v DisableChainedReceive /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v disabledirectAcceptEx /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v DoNotHoldNICBuffers /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v DynamicSendBufferDisable /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v FastSendDatagramThreshold /t REG_DWORD /d 1024 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v FastCopyReceiveThreshold /t REG_DWORD /d 1024 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v IgnoreOrderlyRelease /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v IgnorePushBitOnReceives /t REG_DWORD /d 1 /f >nul
echo  %p%[ %roxo%•%p% %p%]%w% Buffer and Address Optimizations Applied. %p%(%roxo%14%p%)%w%

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DownloadMode /t REG_DWORD /d 0 /f >nul
echo  %p%[ %roxo%•%p% %p%]%w% Delivery Optimization disabled. %p%(%roxo%2%p%)%w%

echo.
echo  %p%[ %roxo%•%p% %p%]%w% %roxo%Network Optimization%w% applied %g%successfully%w%! %p%(%roxo%~3s%p%)%w%

echo.
echo  %p%[ %roxo%•%p% %p%]%w% %roxo%Tracking %w%^& %roxo%Telemetry%w% disabled %g%successfully%w%! %p%(%roxo%~3s%p%)%w%

reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v Status /t REG_DWORD /d 0 /f >nul 2>&1
echo  %p%[ %roxo%•%p% %p%]%w% Location Service disabled. %p%(%roxo%1%p%)%w%


:: ----------------------------
:: Completion
:: ----------------------------
echo.
echo ==============================================
echo REGISTRY OPTIMIZATION COMPLETE!
echo ==============================================
echo.
echo Important notes:
echo - Some changes require restart to take effect
echo - Check your hardware compatibility
echo - Monitor system stability after changes
echo.
pause

:: Refresh system
taskkill /f /im explorer.exe >nul
start explorer.exe
exit /b 0
