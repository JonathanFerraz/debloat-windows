# ==============================================
# R Y Z Ξ N Optimizer
# Version: 3.0 | Date: 2025-07-25
# ==============================================

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$SkipHostsFile,
    [switch]$SkipNvidia,
    [switch]$SkipVS,
    [switch]$SkipOffice,
    [switch]$SkipApps,
    [switch]$DisableXboxLoginFeatures,
    [switch]$SkipBackup,
    [switch]$DisableNotifications
)

#================================================================================
# SCRIPT INITIALIZATION
#================================================================================

# ----------------------------
# Initial Setup
# ----------------------------
$Host.UI.RawUI.WindowTitle = "Ryzen Optimizer v3.0"
Clear-Host

# Import shared module
Import-Module "$PSScriptRoot\..\lib\RyzenOptimizer.psm1" -ErrorAction Stop

# Backup telemetry before making changes
if (-not $SkipBackup) {
    & "$PSScriptRoot\..\backup\telemetry-backup.ps1"
}

Write-Host ""
Write-Host "==============================================" -ForegroundColor Green
Write-Host "                REMOVE TELEMETRY              " -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green



Write-Host "Starting comprehensive privacy tweaks and telemetry disabling..." -ForegroundColor Yellow
Write-Host "Script will run with the following sections skipped: " -ForegroundColor Yellow
if ($SkipHostsFile) { Write-Host "- Hosts File" -ForegroundColor Red }
if ($SkipNvidia) { Write-Host "- NVIDIA" -ForegroundColor Red }
if ($SkipVS) { Write-Host "- Visual Studio" -ForegroundColor Red }
if ($SkipOffice) { Write-Host "- Microsoft Office" -ForegroundColor Red }
if ($SkipApps) { Write-Host "- Other Applications" -ForegroundColor Red }
if ($DisableXboxLoginFeatures) { Write-Host "- Xbox Login Features" -ForegroundColor Red }

# Capture counters for this run without resetting the shared module.
$counterBefore = (Get-OptimizerCounters).Clone()

#region --- Hosts File Modification ---
if (-not $SkipHostsFile) {
    $hostsPath = "$env:windir\System32\drivers\etc\hosts"
    $adobeUrl = "https://a.dove.isdumb.one/list.txt"
    try {
        $adobeContent = (Invoke-WebRequest -Uri $adobeUrl -UseBasicParsing -ErrorAction Stop).Content
        if ($adobeContent -is [byte[]]) { $adobeContent = [Text.Encoding]::UTF8.GetString($adobeContent) }
        Add-HostsEntries -Path $hostsPath -Lines ($adobeContent -split '\r?\n')
    } catch { Write-Warning "Adobe blocklist failed: $($_.Exception.Message)" }

    $telemetryDomains = @"
0.0.0.0 vortex.data.microsoft.com
0.0.0.0 settings-win.data.microsoft.com
0.0.0.0 watson.telemetry.microsoft.com
0.0.0.0 telemetry.microsoft.com
0.0.0.0 telecommand.telemetry.microsoft.com
0.0.0.0 services.wes.df.telemetry.microsoft.com
0.0.0.0 sqm.df.telemetry.microsoft.com
0.0.0.0 telemetry.nvidia.com
0.0.0.0 telemetry.amd.com
0.0.0.0 feedback.microsoft.com
0.0.0.0 diagnostics.support.microsoft.com
0.0.0.0 vortex-win.data.microsoft.com
0.0.0.0 telemetry.appex.bing.net
0.0.0.0 statsfe2.ws.microsoft.com
0.0.0.0 statsfe1.ws.microsoft.com
0.0.0.0 telemetry.urs.microsoft.com
0.0.0.0 settings.data.microsoft.com
0.0.0.0 api.amp.azure.com
"@
    if ($DisableXboxLoginFeatures) {
        $telemetryDomains += "`n0.0.0.0 login.live.com"
    }
    try { Add-HostsEntries -Path $hostsPath -Lines ($telemetryDomains -split '\r?\n') }
    catch { Write-Warning "Telemetry hosts update failed: $($_.Exception.Message)" }
}
#endregion

#region --- Disable Services ---
Write-Host "--- Section: Disabling Services ---" -ForegroundColor Green
Set-ServiceState -ServiceNames @("gupdate", "gupdatem") -StartupType "Disabled"
Set-ServiceState -ServiceNames @("AdobeARMservice", "adobeupdateservice") -StartupType "Disabled"

# Using 'Manual' as it's the valid equivalent for the 'demand' parameter in 'sc.exe'
Set-ServiceState -ServiceNames @("diagnosticshub.standardcollector.service", "diagsvc", "wercplsupport") -StartupType "Manual"
#endregion

#region --- Disable Scheduled Tasks ---
Write-Host "--- Section: Disabling Scheduled Tasks ---" -ForegroundColor Green
$tasksToDisable = @(
    "\Adobe Acrobat Update Task",
    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
    "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
    "\Microsoft\Windows\Autochk\Proxy",
    "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
    "\Microsoft\Windows\Feedback\Siuf\DmClient",
    "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
    "\Microsoft\Windows\Windows Error Reporting\QueueReporting",
    "\Microsoft\Windows\Maps\MapsUpdateTask",
    "\Microsoft\Office\OfficeTelemetryAgentFallBack", "\Microsoft\Office\OfficeTelemetryAgentLogOn",
    "\Microsoft\Office\OfficeTelemetryAgentFallBack2016", "\Microsoft\Office\OfficeTelemetryAgentLogOn2016",
    "\Microsoft\Office\Office 15 Subscription Heartbeat", "\Microsoft\Office\Office 16 Subscription Heartbeat",
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser Exp",
    "\Microsoft\Windows\Application Experience\StartupAppTask",
    "\Microsoft\Windows\Application Experience\PcaPatchDbTask",
    "\Microsoft\Windows\Application Experience\MareBackup"
)
Disable-ScheduledTasksByPath -TaskPaths $tasksToDisable
#endregion

#region --- Main Registry Modifications ---
Write-Host "--- Section: Applying All Registry Tweaks ---" -ForegroundColor Green

# PowerShell Telemetry
[Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', '1', 'Machine')

if (-not $SkipNvidia) {
    Write-Host "Applying NVIDIA Tweaks..."
    Set-RegistryValue "HKLM:\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" "OptInOrOutPreference" 0
    Set-RegistryValue "HKLM:\SOFTWARE\NVIDIA Corporation\Global\FTS" "EnableRID44231" 0
    Set-RegistryValue "HKLM:\SOFTWARE\NVIDIA Corporation\Global\FTS" "EnableRID64640" 0
    Set-RegistryValue "HKLM:\SOFTWARE\NVIDIA Corporation\Global\FTS" "EnableRID66610" 0
    Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" "SendTelemetryData" 0
    Disable-ScheduledTasksByPath -TaskPaths @("\NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}", "\NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}", "\NvTmRepOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}")
}

if (-not $SkipVS) {
    Write-Host "Applying Visual Studio Tweaks..."
    Set-RegistryValue "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\14.0\SQM" "OptIn" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM" "OptIn" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\16.0\SQM" "OptIn" 0
    Set-RegistryValue "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\17.0\SQM" "OptIn" 0
    Set-RegistryValue "HKLM:\Software\Policies\Microsoft\VisualStudio\SQM" "OptIn" 0
    Set-RegistryValue "HKCU:\Software\Microsoft\VisualStudio\Telemetry" "TurnOffSwitch" 1
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" "DisableFeedbackDialog" 1
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" "DisableEmailInput" 1
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" "DisableScreenshotCapture" 1
    Remove-RegistryProperty "HKLM:\Software\Microsoft\VisualStudio\DiagnosticsHub" "LogLevel"
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\IntelliCode" "DisableRemoteAnalysis" 1
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\VSCommon\16.0\IntelliCode" "DisableRemoteAnalysis" 1
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\VSCommon\17.0\IntelliCode" "DisableRemoteAnalysis" 1
}

if (-not $SkipApps) {
    Write-Host "Applying Other Application Tweaks (Media Player, CCleaner)..."
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences" "UsageTracking" 0
    Set-RegistryValue "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" "PreventCDDVDMetadataRetrieval" 1
    Set-RegistryValue "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" "PreventMusicFileMetadataRetrieval" 1
    Set-RegistryValue "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" "PreventRadioPresetsRetrieval" 1
    Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" "DisableOnline" 1
    Set-RegistryValue "HKCU:\Software\Piriform\CCleaner" "Monitoring" 0
    Set-RegistryValue "HKCU:\Software\Piriform\CCleaner" "HelpImproveCCleaner" 0
    Set-RegistryValue "HKCU:\Software\Piriform\CCleaner" "SystemMonitoring" 0
    Set-RegistryValue "HKCU:\Software\Piriform\CCleaner" "UpdateAuto" 0
    Set-RegistryValue "HKCU:\Software\Piriform\CCleaner" "UpdateCheck" 0
    Set-RegistryValue "HKCU:\Software\Piriform\CCleaner" "CheckTrialOffer" 0
    Set-RegistryValue "HKLM:\Software\Piriform\CCleaner" "(Cfg)HealthCheck" 0
    Set-RegistryValue "HKLM:\Software\Piriform\CCleaner" "(Cfg)QuickClean" 0
    Set-RegistryValue "HKLM:\Software\Piriform\CCleaner" "(Cfg)QuickCleanIpm" 0
    Set-RegistryValue "HKLM:\Software\Piriform\CCleaner" "(Cfg)GetIpmForTrial" 0
    Set-RegistryValue "HKLM:\Software\Piriform\CCleaner" "(Cfg)SoftwareUpdater" 0
    Set-RegistryValue "HKLM:\Software\Piriform\CCleaner" "(Cfg)SoftwareUpdaterIpm" 0
}

if (-not $SkipOffice) {
    Write-Host "Applying Office Tweaks..."
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Mail" "EnableLogging" 0
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Mail" "EnableLogging" 0
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Calendar" "EnableCalendarLogging" 0
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Calendar" "EnableCalendarLogging" 0
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Office\15.0\Word\Options" "EnableLogging" 0
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Options" "EnableLogging" 0
    Set-RegistryValue "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" "EnableLogging" 0
    Set-RegistryValue "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" "EnableLogging" 0
    Set-RegistryValue "HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" "EnableUpload" 0
    Set-RegistryValue "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" "EnableUpload" 0
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" "DisableTelemetry" 1
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" "DisableTelemetry" 1
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" "VerboseLogging" 0
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" "VerboseLogging" 0
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common" "QMEnable" 0
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common" "QMEnable" 0
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Feedback" "Enabled" 0
    Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Feedback" "Enabled" 0
}

Write-Host "Applying Windows OS Tweaks..."

### Windows Registry Tweaks ###
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowDesktopAnalyticsProcessing" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowDeviceNameInTelemetry" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "MicrosoftEdgeDataOptIn" 0 | Out-Null
# Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowWUfBCloudProcessing" 0
# Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowUpdateComplianceProcessing" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowCommercialDataPipeline" 0 | Out-Null
Set-RegistryValue "HKLM:\Software\Policies\Microsoft\SQMClient\Windows" "CEIPEnable" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0 | Out-Null
Set-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" "DisableOneSettingsDownloads" 1 | Out-Null
Set-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" "NoGenTicket" 1 | Out-Null
Set-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" "Disabled" 1 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" "Disabled" 1 | Out-Null
Set-RegistryValue "HKLM:\Software\Microsoft\Windows\Windows Error Reporting\Consent" "DefaultConsent" 0 | Out-Null
Set-RegistryValue "HKLM:\Software\Microsoft\Windows\Windows Error Reporting\Consent" "DefaultOverrideBehavior" 1 | Out-Null
Set-RegistryValue "HKLM:\Software\Microsoft\Windows\Windows Error Reporting" "DontSendAdditionalData" 1 | Out-Null
Set-RegistryValue "HKLM:\Software\Microsoft\Windows\Windows Error Reporting" "LoggingDisabled" 1 | Out-Null
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "ContentDeliveryAllowed" 0 | Out-Null
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "OemPreInstalledAppsEnabled" 0 | Out-Null
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEnabled" 0 | Out-Null
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEverEnabled" 0 | Out-Null
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SilentInstalledAppsEnabled" 0 | Out-Null
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SystemPaneSuggestionsEnabled" 0 | Out-Null
if ($DisableNotifications) { Set-RegistryValue "HKLM:\Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications" "EnableAccountNotifications" 0 | Out-Null }
if ($DisableNotifications) { Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications" "EnableAccountNotifications" 0 | Out-Null }
if ($DisableNotifications) { Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" "NOC_GLOBAL_SETTING_TOASTS_ENABLED" 0 | Out-Null }
Set-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\EdgeUI" "DisableMFUTracking" 1 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" "DisableMFUTracking" 1 | Out-Null
Set-RegistryValue "HKCU:\Control Panel\International\User Profile" "HttpAcceptLanguageOptOut" 1 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "PublishUserActivities" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "UploadUserActivities" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessAccountInfo" $(if ($DisableXboxLoginFeatures) { 2 } else { 1 }) | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessCalendar" 2 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessCallHistory" 2 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessCamera" 2 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessContacts" 2 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessEmail" 2 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessMessaging" 2 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessMicrophone" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessMotion" 2 | Out-Null
if ($DisableNotifications) { Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessNotifications" 2 | Out-Null }
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessPhone" 2 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessPhone_UserInControlOfTheseApps" @() "MultiString" | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessPhone_ForceAllowTheseApps" @() "MultiString" | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessPhone_ForceDenyTheseApps" @() "MultiString" | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessRadios" 2 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessTasks" 2 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsGetDiagnosticInfo" 2 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableSettingSync" 2 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableSettingSyncUserOverride" 1 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableSyncOnPaidNetwork" 1 | Out-Null
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" "SyncPolicy" 5 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableApplicationSettingSync" 2 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableApplicationSettingSyncUserOverride" 1 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableAppSyncSettingSync" 2 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableAppSyncSettingSyncUserOverride" 1 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableCredentialsSettingSync" 2 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableCredentialsSettingSyncUserOverride" 1 | Out-Null
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" "Enabled" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableDesktopThemeSettingSync" 2 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableDesktopThemeSettingSyncUserOverride" 1 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisablePersonalizationSettingSync" 2 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisablePersonalizationSettingSyncUserOverride" 1 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableStartLayoutSettingSync" 2 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableStartLayoutSettingSyncUserOverride" 1 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableWebBrowserSettingSync" 2 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableWebBrowserSettingSyncUserOverride" 1 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableWindowsSettingSync" 2 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableWindowsSettingSyncUserOverride" 1 | Out-Null
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" "Enabled" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" "SearchOrderConfig" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\Config" "DODownloadMode" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\Config" "DownloadMode" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "ConnectedSearchPrivacy" 3 | Out-Null
Set-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows\Explorer" "DisableSearchHistory" 1 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowSearchToUseLocation" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "EnableDynamicContentInWSB" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "ConnectedSearchUseWeb" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "DisableWebSearch" 1 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "DisableSearchBoxSuggestions" 1 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "PreventUnwantedAddIns" " " "String" | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "PreventRemoteQueries" 1 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AlwaysUseAutoLangDetection" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowIndexingEncryptedStoresOrItems" 0 | Out-Null
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "DisableSearchBoxSuggestions" 1 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "CortanaInAmbientMode" 0 | Out-Null
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "BingSearchEnabled" 0 | Out-Null
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowCortanaButton" 0 | Out-Null
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" "CanCortanaBeEnabled" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "ConnectedSearchUseWebOverMeteredConnections" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortanaAboveLock" 0 | Out-Null
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" "IsDynamicSearchBoxEnabled" 1 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" "value" 0 | Out-Null
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "AllowSearchToUseLocation" 1 | Out-Null
Set-RegistryValue "HKCU:\Software\Microsoft\Speech_OneCore\Preferences" "ModelDownloadAllowed" 0 | Out-Null
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" "IsDeviceSearchHistoryEnabled" 1 | Out-Null
Set-RegistryValue "HKCU:\Software\Microsoft\Speech_OneCore\Preferences" "VoiceActivationOn" 0 | Out-Null
Set-RegistryValue "HKCU:\Software\Microsoft\Speech_OneCore\Preferences" "VoiceActivationEnableAboveLockscreen" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" "DisableVoice" 1 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" 0 | Out-Null
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "DeviceHistoryEnabled" 0 | Out-Null
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "HistoryViewEnabled" 0 | Out-Null
Set-RegistryValue "HKLM:\Software\Microsoft\Speech_OneCore\Preferences" "VoiceActivationDefaultOn" 0 | Out-Null
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" "CortanaEnabled" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "CortanaEnabled" 0 | Out-Null
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" "IsMSACloudSearchEnabled" 0 | Out-Null
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" "IsAADCloudSearchEnabled" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCloudSearch" 0 | Out-Null
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "VoiceShortcut" 0 | Out-Null
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" "CortanaConsent" 0 | Out-Null
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" "NumberOfSIUFInPeriod" 0 | Out-Null
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" "PeriodInDays" 0 | Out-Null
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" "NumberOfNotificationsSent" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "DoNotShowFeedbackNotifications" 1 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DoNotShowFeedbackNotifications" 1 | Out-Null
Set-RegistryValue "HKCU:\Software\Policies\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1 | Out-Null
Set-RegistryValue "HKCU:\Software\Policies\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1 | Out-Null
Set-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" "PreventHandwritingErrorReports" 1 | Out-Null
Set-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" "PreventHandwritingErrorReports" 1 | Out-Null
Set-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\TabletPC" "PreventHandwritingDataSharing" 1 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" "PreventHandwritingDataSharing" 1 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" "AllowInputPersonalization" 0 | Out-Null
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" 0 | Out-Null
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" "AcceptedPrivacyPolicy" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableSoftLanding" 1 | Out-Null
Set-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" "DisableWindowsSpotlightFeatures" 1 | Out-Null
Set-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1 | Out-Null
Set-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" "DisableTailoredExperiencesWithDiagnosticData" 1 | Out-Null
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" "DisabledByGroupPolicy" 1 | Out-Null
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338393Enabled" 0 | Out-Null
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-353694Enabled" 0 | Out-Null
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-353696Enabled" 0 | Out-Null
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338387Enabled" 0 | Out-Null
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338388Enabled" 0 | Out-Null
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338389Enabled" 0 | Out-Null
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-353698Enabled" 0 | Out-Null

# NVIDIA/AMD/INTEL  ###

Set-RegistryValue "HKLM:\SOFTWARE\NVIDIA Corporation\Global\NvTelemetry" "Enabled" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\AMD\ACE\Settings\General" "EnableTelemetry" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Intel\Display\igfxcui\Telemetry" "EnableTelemetry" 0 | Out-Null

#endregion

#region ### Additional Telemetry Tweaks  ###
Write-Host "Applying Additional OS & App Tweaks..."

# Microsoft Edge Expanded
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "MetricsReportingEnabled" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "BrowserSignin" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "ShoppingAssistantEnabled" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "PersonalizationReportingEnabled" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "ShowRecommendationsEnabled" 0 | Out-Null

# Game DVR
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" "AppCaptureEnabled" 0 | Out-Null
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" 0 | Out-Null

# Location and Sensors
Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" "Status" 0 | Out-Null
#endregion

#================================================================================
# SCRIPT COMPLETION
#================================================================================

#region --- Finalization ---
Write-Host "------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "SCRIPT EXECUTION SUMMARY" -ForegroundColor Yellow
Write-Host "------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "Registry values created/modified: $((Get-OptimizerCounters).RegistrySuccess - $counterBefore.RegistrySuccess)" -ForegroundColor Cyan
Write-Host "Services disabled/modified: $((Get-OptimizerCounters).ServiceSuccess - $counterBefore.ServiceSuccess)" -ForegroundColor Cyan
Write-Host "Scheduled tasks disabled: $((Get-OptimizerCounters).TaskSuccess - $counterBefore.TaskSuccess)" -ForegroundColor Cyan
Write-Host ""
Write-Host "Comprehensive privacy tweaking script has completed." -ForegroundColor Green
Write-Host "It is HIGHLY RECOMMENDED to reboot your system for all changes to take full effect." -ForegroundColor Yellow
#endregion