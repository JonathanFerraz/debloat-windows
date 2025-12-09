# ==============================================
# R Y Z Ξ N Optimizer
# Version: 2.0 | Date: 2025-07-25
# ==============================================

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$SkipHostsFile,
    [switch]$SkipNvidia,
    [switch]$SkipVS,
    [switch]$SkipOffice,
    [switch]$SkipApps
)

#================================================================================
# SCRIPT INITIALIZATION
#================================================================================

# ----------------------------
# Initial Setup
# ----------------------------
$Host.UI.RawUI.WindowTitle = "Ryzen Optimizer v2.0"
Clear-Host

# Backup telemetry before making changes
& "$PSScriptRoot\..\backup\telemetry-backup.ps1"

Write-Host ""
Write-Host "==============================================" -ForegroundColor Green
Write-Host "                REMOVE TELEMETRY              " -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green

# Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script must be run as Administrator. Please right-click the script and select 'Run with PowerShell (Admin)'."
    Start-Sleep -Seconds 10
    exit
}

Write-Host "Starting comprehensive privacy tweaks and telemetry disabling..." -ForegroundColor Yellow
Write-Host "Script will run with the following sections skipped: " -ForegroundColor Yellow
if ($SkipHostsFile) { Write-Host "- Hosts File" -ForegroundColor Red }
if ($SkipNvidia) { Write-Host "- NVIDIA" -ForegroundColor Red }
if ($SkipVS) { Write-Host "- Visual Studio" -ForegroundColor Red }
if ($SkipOffice) { Write-Host "- Microsoft Office" -ForegroundColor Red }
if ($SkipApps) { Write-Host "- Other Applications" -ForegroundColor Red }

# Global counters for summary
$global:regChanges = 0
$global:serviceChanges = 0
$global:taskChanges = 0

#endregion

#================================================================================
# HELPER FUNCTIONS
#================================================================================

#region --- Helper Functions ---

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$Type = 'DWord' # Changed to string to handle all types easily
    )
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
        Write-Verbose "Registry value '$Name' set at '$Path'."
        $global:regChanges++
    }
    catch {
        Write-Error "Failed to set registry value '$Name' at '$Path'. Error: $($_.Exception.Message)"
    }
}

function Remove-RegistryProperty {
    param(
        [string]$Path,
        [string]$Name
    )
    if (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue) {
        try {
            Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction Stop
            Write-Verbose "Registry property '$Name' removed from '$Path'."
            $global:regChanges++
        }
        catch {
            Write-Error "Failed to remove registry property '$Name' from '$Path'. Error: $($_.Exception.Message)"
        }
    }
}

function Set-ServiceState {
    param(
        [string[]]$ServiceNames,
        [ValidateSet('Disabled', 'Automatic', 'Manual')]
        [string]$StartupType,
        [string]$Status = "Stopped"
    )
    foreach ($service in $ServiceNames) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc) {
            try {
                Set-Service -Name $service -StartupType $StartupType -ErrorAction Stop
                # Stop the service if it is running
                if ($svc.Status -eq 'Running') {
                    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                }
                Write-Host "Service '$service' startup type set to '$StartupType'." -ForegroundColor Cyan
                $global:serviceChanges++
            }
            catch {
                Write-Error "Failed to set service '$service' state. Error: $($_.Exception.Message)"
            }
        }
    }
}

function Disable-ScheduledTasksByPath {
    param(
        [string[]]$TaskPaths
    )
    foreach ($taskPath in $TaskPaths) {
        $task = Get-ScheduledTask -TaskPath $taskPath -ErrorAction SilentlyContinue
        if ($task -and $task.State -ne 'Disabled') {
            try {
                $task | Disable-ScheduledTask
                Write-Host "Scheduled Task '$taskPath' has been disabled." -ForegroundColor Cyan
                $global:taskChanges++
            }
            catch {
                Write-Error "Failed to disable scheduled task '$taskPath'. Error: $($_.Exception.Message)"
            }
        }
    }
}

#endregion

#================================================================================
# SCRIPT BODY
#================================================================================

#region --- Hosts File Modification ---
if (-not $SkipHostsFile) {
    $hostsPath = "$env:windir\System32\drivers\etc\hosts"
    $downloadedList = Join-Path $env:TEMP "list.txt"
    $adobeUrl = "https://a.dove.isdumb.one/list.txt"
    try {
        Invoke-WebRequest -Uri $adobeUrl -OutFile $downloadedList -UseBasicParsing
        Get-Content $downloadedList | Add-Content -Path $hostsPath
        Write-Host "Adobe blocklist entries successfully added."
    }
    catch { Write-Error "Failed to download the Adobe blocklist. Error: $($_.Exception.Message)" }
    finally { if (Test-Path -Path $downloadedList) { Remove-Item -Path $downloadedList -Force } }

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
0.0.0.0 login.live.com
0.0.0.0 api.amp.azure.com
"@
    $telemetryDomains | Add-Content -Path $hostsPath
    Write-Host "Common telemetry domains added to hosts file."
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
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowDesktopAnalyticsProcessing" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowDeviceNameInTelemetry" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "MicrosoftEdgeDataOptIn" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowWUfBCloudProcessing" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowUpdateComplianceProcessing" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowCommercialDataPipeline" 0
Set-RegistryValue "HKLM:\Software\Policies\Microsoft\SQMClient\Windows" "CEIPEnable" 0
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0
Set-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" "DisableOneSettingsDownloads" 1
Set-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" "NoGenTicket" 1
Set-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting" "Disabled" 1
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" "Disabled" 1
Set-RegistryValue "HKLM:\Software\Microsoft\Windows\Windows Error Reporting\Consent" "DefaultConsent" 0
Set-RegistryValue "HKLM:\Software\Microsoft\Windows\Windows Error Reporting\Consent" "DefaultOverrideBehavior" 1
Set-RegistryValue "HKLM:\Software\Microsoft\Windows\Windows Error Reporting" "DontSendAdditionalData" 1
Set-RegistryValue "HKLM:\Software\Microsoft\Windows\Windows Error Reporting" "LoggingDisabled" 1
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "ContentDeliveryAllowed" 0
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "OemPreInstalledAppsEnabled" 0
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEnabled" 0
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEverEnabled" 0
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SilentInstalledAppsEnabled" 0
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SystemPaneSuggestionsEnabled" 0
Set-RegistryValue "HKLM:\Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications" "EnableAccountNotifications" 0
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications" "EnableAccountNotifications" 0
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" "NOC_GLOBAL_SETTING_TOASTS_ENABLED" 0
Set-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\EdgeUI" "DisableMFUTracking" 1
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" "DisableMFUTracking" 1
Set-RegistryValue "HKCU:\Control Panel\International\User Profile" "HttpAcceptLanguageOptOut" 1
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "PublishUserActivities" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "UploadUserActivities" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessAccountInfo" 2
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessCalendar" 2
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessCallHistory" 2
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessCamera" 2
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessContacts" 2
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessEmail" 2
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessMessaging" 2
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessMicrophone" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessMotion" 2
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessNotifications" 2
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessPhone" 2
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessPhone_UserInControlOfTheseApps" @() "MultiString"
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessPhone_ForceAllowTheseApps" @() "MultiString"
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessPhone_ForceDenyTheseApps" @() "MultiString"
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessRadios" 2
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessTasks" 2
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsGetDiagnosticInfo" 2
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableSettingSync" 2
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableSettingSyncUserOverride" 1
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableSyncOnPaidNetwork" 1
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" "SyncPolicy" 5
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableApplicationSettingSync" 2
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableApplicationSettingSyncUserOverride" 1
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableAppSyncSettingSync" 2
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableAppSyncSettingSyncUserOverride" 1
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableCredentialsSettingSync" 2
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableCredentialsSettingSyncUserOverride" 1
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" "Enabled" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableDesktopThemeSettingSync" 2
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableDesktopThemeSettingSyncUserOverride" 1
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisablePersonalizationSettingSync" 2
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisablePersonalizationSettingSyncUserOverride" 1
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableStartLayoutSettingSync" 2
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableStartLayoutSettingSyncUserOverride" 1
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableWebBrowserSettingSync" 2
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableWebBrowserSettingSyncUserOverride" 1
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableWindowsSettingSync" 2
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" "DisableWindowsSettingSyncUserOverride" 1
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" "Enabled" 0
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" "SearchOrderConfig" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\Config" "DODownloadMode" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\Config" "DownloadMode" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "ConnectedSearchPrivacy" 3
Set-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows\Explorer" "DisableSearchHistory" 1
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowSearchToUseLocation" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "EnableDynamicContentInWSB" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "ConnectedSearchUseWeb" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "DisableWebSearch" 1
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "DisableSearchBoxSuggestions" 1
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "PreventUnwantedAddIns" " " "String"
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "PreventRemoteQueries" 1
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AlwaysUseAutoLangDetection" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowIndexingEncryptedStoresOrItems" 0
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "DisableSearchBoxSuggestions" 1
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "CortanaInAmbientMode" 0
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "BingSearchEnabled" 0
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowCortanaButton" 0
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" "CanCortanaBeEnabled" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "ConnectedSearchUseWebOverMeteredConnections" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortanaAboveLock" 0
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" "IsDynamicSearchBoxEnabled" 1
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" "value" 0
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "AllowSearchToUseLocation" 1
Set-RegistryValue "HKCU:\Software\Microsoft\Speech_OneCore\Preferences" "ModelDownloadAllowed" 0
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" "IsDeviceSearchHistoryEnabled" 1
Set-RegistryValue "HKCU:\Software\Microsoft\Speech_OneCore\Preferences" "VoiceActivationOn" 0
Set-RegistryValue "HKCU:\Software\Microsoft\Speech_OneCore\Preferences" "VoiceActivationEnableAboveLockscreen" 0
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" "DisableVoice" 1
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" 0
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "DeviceHistoryEnabled" 0
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "HistoryViewEnabled" 0
Set-RegistryValue "HKLM:\Software\Microsoft\Speech_OneCore\Preferences" "VoiceActivationDefaultOn" 0
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" "CortanaEnabled" 0
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "CortanaEnabled" 0
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" "IsMSACloudSearchEnabled" 0
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" "IsAADCloudSearchEnabled" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCloudSearch" 0
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "VoiceShortcut" 0
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" "CortanaConsent" 0
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" "NumberOfSIUFInPeriod" 0
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" "PeriodInDays" 0
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" "NumberOfNotificationsSent" 0
Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "DoNotShowFeedbackNotifications" 1
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DoNotShowFeedbackNotifications" 1
Set-RegistryValue "HKCU:\Software\Policies\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1
Set-RegistryValue "HKCU:\Software\Policies\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1
Set-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" "PreventHandwritingErrorReports" 1
Set-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports" "PreventHandwritingErrorReports" 1
Set-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\TabletPC" "PreventHandwritingDataSharing" 1
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" "PreventHandwritingDataSharing" 1
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" "AllowInputPersonalization" 0
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" 0
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" "AcceptedPrivacyPolicy" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableSoftLanding" 1
Set-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" "DisableWindowsSpotlightFeatures" 1
Set-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1
Set-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" "DisableTailoredExperiencesWithDiagnosticData" 1
Set-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" "DisabledByGroupPolicy" 1
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338393Enabled" 0
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-353694Enabled" 0
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-353696Enabled" 0
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338387Enabled" 0
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338388Enabled" 0
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338389Enabled" 0
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-353698Enabled" 0

# NVIDIA/AMD/INTEL  ###

Set-RegistryValue "HKLM:\SOFTWARE\NVIDIA Corporation\Global\NvTelemetry" "Enabled" 0
Set-RegistryValue "HKLM:\SOFTWARE\AMD\ACE\Settings\General" "EnableTelemetry" 0
Set-RegistryValue "HKLM:\SOFTWARE\Intel\Display\igfxcui\Telemetry" "EnableTelemetry" 0

#endregion

#region ### Additional Telemetry Tweaks  ###
Write-Host "Applying Additional OS & App Tweaks..."

# Microsoft Edge Expanded
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "MetricsReportingEnabled" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "BrowserSignin" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "ShoppingAssistantEnabled" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "PersonalizationReportingEnabled" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Edge" "ShowRecommendationsEnabled" 0

# Game DVR
Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" "AppCaptureEnabled" 0
Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" 0

# Location and Sensors
Set-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" "Status" 0
#endregion

#================================================================================
# SCRIPT COMPLETION
#================================================================================

#region --- Finalization ---
Write-Host "------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "SCRIPT EXECUTION SUMMARY" -ForegroundColor Yellow
Write-Host "------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "Registry values created/modified: $global:regChanges" -ForegroundColor Cyan
Write-Host "Services disabled/modified: $global:serviceChanges" -ForegroundColor Cyan
Write-Host "Scheduled tasks disabled: $global:taskChanges" -ForegroundColor Cyan
Write-Host ""
Write-Host "Comprehensive privacy tweaking script has completed." -ForegroundColor Green
Write-Host "It is HIGHLY RECOMMENDED to reboot your system for all changes to take full effect." -ForegroundColor Yellow
#endregion