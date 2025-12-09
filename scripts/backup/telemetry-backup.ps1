#Requires -RunAsAdministrator

# ----------------------------
# Initial Setup
# ----------------------------
Clear-Host
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host "      BACKUP SCRIPT FOR RYZEN OPTIMIZER       " -ForegroundColor Yellow
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
$folderName = "telemetry-$timestamp"
$backupDir = Join-Path -Path $backupBaseDir -ChildPath $folderName
New-Item -Path $backupDir -ItemType Directory -Force | Out-Null

Write-Host "Backup location will be: $backupDir" -ForegroundColor Cyan

# Define CSV file paths
$regBackupFile = Join-Path $backupDir "telemetry-registry-backup.csv"
$serviceBackupFile = Join-Path $backupDir "telemetry-services-backup.csv"
$taskBackupFile = Join-Path $backupDir "telemetry-tasks-backup.csv"
$envVarBackupFile = Join-Path $backupDir "telemetry-env-vars-backup.csv"

# Arrays to hold backup data
$regBackupData = @()
$serviceBackupData = @()
$taskBackupData = @()
$envVarBackupData = @()

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
                # Get the actual type from the key itself
                $key = Get-Item -Path $Path
                $currentType = $key.GetValueKind($Name)
            }
        }
    }
    catch {
        Write-Warning "Could not read registry value: $Path \ $Name. It may be protected."
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

# --- 1. Hosts File Backup ---
Write-Host "--- Backing up Hosts file..." -ForegroundColor Green
$hostsPath = "$env:windir\System32\drivers\etc\hosts"
if (Test-Path $hostsPath) {
    Copy-Item -Path $hostsPath -Destination (Join-Path $backupDir "hosts.backup") -Force
    Write-Host "Hosts file successfully backed up."
} else {
    Write-Warning "Hosts file not found at $hostsPath."
}

# --- 2. Services Backup ---
Write-Host "--- Backing up Services states..." -ForegroundColor Green
$servicesToBackup = @(
    "gupdate", "gupdatem", "AdobeARMservice", "adobeupdateservice",
    "diagnosticshub.standardcollector.service", "diagsvc", "wercplsupport", "lfsvc"
)
foreach ($serviceName in $servicesToBackup) {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        $serviceBackupData += [PSCustomObject]@{
            Name         = $service.Name
            StartupType  = $service.StartupType
            Status       = $service.Status
        }
        Write-Verbose "Backed up service: $($service.Name)"
    }
}
Write-Host "Found and backed up $($serviceBackupData.Count) services."

# --- 3. Scheduled Tasks Backup ---
Write-Host "--- Backing up Scheduled Tasks states..." -ForegroundColor Green
$tasksToBackup = @(
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
    "\Microsoft\Windows\Application Experience\MareBackup",
    "\NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}", 
    "\NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}", 
    "\NvTmRepOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}"
)
foreach ($taskPath in $tasksToBackup) {
    $task = Get-ScheduledTask -TaskPath $taskPath -ErrorAction SilentlyContinue
    if ($task) {
        $taskBackupData += [PSCustomObject]@{
            Path  = $task.TaskPath
            Name  = $task.TaskName
            State = $task.State
        }
        Write-Verbose "Backed up task: $($task.TaskPath)"
    }
}
Write-Host "Found and backed up $($taskBackupData.Count) scheduled tasks."


# --- 4. Environment Variable Backup ---
Write-Host "--- Backing up Environment Variables..." -ForegroundColor Green
$envVar = Get-RegistryValueBackup -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "POWERSHELL_TELEMETRY_OPTOUT"
$envVarBackupData += $envVar
Write-Host "Backed up POWERSHELL_TELEMETRY_OPTOUT variable."

# --- 5. Registry Backup ---
Write-Host "--- Backing up all Registry values..." -ForegroundColor Green
# Create a list of all registry modifications from the telemetry.ps1 script
# Each item is a hashtable: @{Path='...'; Name='...'}
$registryKeysToBackup = @(
    @{Path="HKLM:\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client"; Name="OptInOrOutPreference"};
    @{Path="HKLM:\SOFTWARE\NVIDIA Corporation\Global\FTS"; Name="EnableRID44231"};
    @{Path="HKLM:\SOFTWARE\NVIDIA Corporation\Global\FTS"; Name="EnableRID64640"};
    @{Path="HKLM:\SOFTWARE\NVIDIA Corporation\Global\FTS"; Name="EnableRID66610"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup"; Name="SendTelemetryData"};
    @{Path="HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\14.0\SQM"; Name="OptIn"};
    @{Path="HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM"; Name="OptIn"};
    @{Path="HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\16.0\SQM"; Name="OptIn"};
    @{Path="HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\17.0\SQM"; Name="OptIn"};
    @{Path="HKLM:\Software\Policies\Microsoft\VisualStudio\SQM"; Name="OptIn"};
    @{Path="HKCU:\Software\Microsoft\VisualStudio\Telemetry"; Name="TurnOffSwitch"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback"; Name="DisableFeedbackDialog"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback"; Name="DisableEmailInput"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback"; Name="DisableScreenshotCapture"};
    @{Path="HKLM:\Software\Microsoft\VisualStudio\DiagnosticsHub"; Name="LogLevel"}; # This one is removed, so we back it up
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\VisualStudio\IntelliCode"; Name="DisableRemoteAnalysis"};
    @{Path="HKCU:\SOFTWARE\Microsoft\VSCommon\16.0\IntelliCode"; Name="DisableRemoteAnalysis"};
    @{Path="HKCU:\SOFTWARE\Microsoft\VSCommon\17.0\IntelliCode"; Name="DisableRemoteAnalysis"};
    @{Path="HKCU:\SOFTWARE\Microsoft\MediaPlayer\Preferences"; Name="UsageTracking"};
    @{Path="HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer"; Name="PreventCDDVDMetadataRetrieval"};
    @{Path="HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer"; Name="PreventMusicFileMetadataRetrieval"};
    @{Path="HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer"; Name="PreventRadioPresetsRetrieval"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\WMDRM"; Name="DisableOnline"};
    @{Path="HKCU:\Software\Piriform\CCleaner"; Name="Monitoring"};
    @{Path="HKCU:\Software\Piriform\CCleaner"; Name="HelpImproveCCleaner"};
    @{Path="HKCU:\Software\Piriform\CCleaner"; Name="SystemMonitoring"};
    @{Path="HKCU:\Software\Piriform\CCleaner"; Name="UpdateAuto"};
    @{Path="HKCU:\Software\Piriform\CCleaner"; Name="UpdateCheck"};
    @{Path="HKCU:\Software\Piriform\CCleaner"; Name="CheckTrialOffer"};
    @{Path="HKLM:\Software\Piriform\CCleaner"; Name="(Cfg)HealthCheck"};
    @{Path="HKLM:\Software\Piriform\CCleaner"; Name="(Cfg)QuickClean"};
    @{Path="HKLM:\Software\Piriform\CCleaner"; Name="(Cfg)QuickCleanIpm"};
    @{Path="HKLM:\Software\Piriform\CCleaner"; Name="(Cfg)GetIpmForTrial"};
    @{Path="HKLM:\Software\Piriform\CCleaner"; Name="(Cfg)SoftwareUpdater"};
    @{Path="HKLM:\Software\Piriform\CCleaner"; Name="(Cfg)SoftwareUpdaterIpm"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Mail"; Name="EnableLogging"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Mail"; Name="EnableLogging"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Calendar"; Name="EnableCalendarLogging"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Calendar"; Name="EnableCalendarLogging"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Office\15.0\Word\Options"; Name="EnableLogging"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Options"; Name="EnableLogging"};
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\OSM"; Name="EnableLogging"};
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\OSM"; Name="EnableLogging"};
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Office\15.0\OSM"; Name="EnableUpload"};
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\OSM"; Name="EnableUpload"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry"; Name="DisableTelemetry"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry"; Name="DisableTelemetry"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Office\Common\ClientTelemetry"; Name="VerboseLogging"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry"; Name="VerboseLogging"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Office\15.0\Common"; Name="QMEnable"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Office\16.0\Common"; Name="QMEnable"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Office\15.0\Common\Feedback"; Name="Enabled"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Feedback"; Name="Enabled"};
    # Windows OS Tweaks (shortened for brevity in comments, all keys are included)
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="AllowDesktopAnalyticsProcessing"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="AllowDeviceNameInTelemetry"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="MicrosoftEdgeDataOptIn"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="AllowWUfBCloudProcessing"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="AllowUpdateComplianceProcessing"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="AllowCommercialDataPipeline"};
    @{Path="HKLM:\Software\Policies\Microsoft\SQMClient\Windows"; Name="CEIPEnable"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name="AllowTelemetry"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="AllowTelemetry"};
    @{Path="HKLM:\Software\Policies\Microsoft\Windows\DataCollection"; Name="DisableOneSettingsDownloads"};
    @{Path="HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"; Name="NoGenTicket"};
    @{Path="HKLM:\Software\Policies\Microsoft\Windows\Windows Error Reporting"; Name="Disabled"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"; Name="Disabled"};
    @{Path="HKLM:\Software\Microsoft\Windows\Windows Error Reporting\Consent"; Name="DefaultConsent"};
    @{Path="HKLM:\Software\Microsoft\Windows\Windows Error Reporting\Consent"; Name="DefaultOverrideBehavior"};
    @{Path="HKLM:\Software\Microsoft\Windows\Windows Error Reporting"; Name="DontSendAdditionalData"};
    @{Path="HKLM:\Software\Microsoft\Windows\Windows Error Reporting"; Name="LoggingDisabled"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="ContentDeliveryAllowed"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="OemPreInstalledAppsEnabled"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="PreInstalledAppsEnabled"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="PreInstalledAppsEverEnabled"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SilentInstalledAppsEnabled"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SystemPaneSuggestionsEnabled"};
    @{Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications"; Name="EnableAccountNotifications"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications"; Name="EnableAccountNotifications"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings"; Name="NOC_GLOBAL_SETTING_TOASTS_ENABLED"};
    @{Path="HKCU:\Software\Policies\Microsoft\Windows\EdgeUI"; Name="DisableMFUTracking"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI"; Name="DisableMFUTracking"};
    @{Path="HKCU:\Control Panel\International\User Profile"; Name="HttpAcceptLanguageOptOut"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="PublishUserActivities"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name="UploadUserActivities"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name="LetAppsAccessAccountInfo"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name="LetAppsAccessCalendar"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name="LetAppsAccessCallHistory"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name="LetAppsAccessCamera"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name="LetAppsAccessContacts"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name="LetAppsAccessEmail"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name="LetAppsAccessLocation"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name="LetAppsAccessMessaging"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name="LetAppsAccessMicrophone"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name="LetAppsAccessMotion"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name="LetAppsAccessNotifications"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name="LetAppsAccessPhone"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name="LetAppsAccessPhone_UserInControlOfTheseApps"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name="LetAppsAccessPhone_ForceAllowTheseApps"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name="LetAppsAccessPhone_ForceDenyTheseApps"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name="LetAppsAccessRadios"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name="LetAppsAccessTasks"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name="LetAppsAccessTrustedDevices"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"; Name="LetAppsGetDiagnosticInfo"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"; Name="DisableSettingSync"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"; Name="DisableSettingSyncUserOverride"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"; Name="DisableSyncOnPaidNetwork"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync"; Name="SyncPolicy"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"; Name="DisableApplicationSettingSync"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"; Name="DisableApplicationSettingSyncUserOverride"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"; Name="DisableAppSyncSettingSync"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"; Name="DisableAppSyncSettingSyncUserOverride"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"; Name="DisableCredentialsSettingSync"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"; Name="DisableCredentialsSettingSyncUserOverride"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials"; Name="Enabled"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"; Name="DisableDesktopThemeSettingSync"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"; Name="DisableDesktopThemeSettingSyncUserOverride"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"; Name="DisablePersonalizationSettingSync"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"; Name="DisablePersonalizationSettingSyncUserOverride"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"; Name="DisableStartLayoutSettingSync"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"; Name="DisableStartLayoutSettingSyncUserOverride"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"; Name="DisableWebBrowserSettingSync"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"; Name="DisableWebBrowserSettingSyncUserOverride"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"; Name="DisableWindowsSettingSync"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync"; Name="DisableWindowsSettingSyncUserOverride"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language"; Name="Enabled"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching"; Name="SearchOrderConfig"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\Config"; Name="DODownloadMode"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\Config"; Name="DownloadMode"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="ConnectedSearchPrivacy"};
    @{Path="HKLM:\Software\Policies\Microsoft\Windows\Explorer"; Name="DisableSearchHistory"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="AllowSearchToUseLocation"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="EnableDynamicContentInWSB"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="ConnectedSearchUseWeb"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="DisableWebSearch"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="DisableSearchBoxSuggestions"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="PreventUnwantedAddIns"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="PreventRemoteQueries"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="AlwaysUseAutoLangDetection"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="AllowIndexingEncryptedStoresOrItems"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"; Name="DisableSearchBoxSuggestions"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"; Name="CortanaInAmbientMode"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"; Name="BingSearchEnabled"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="ShowCortanaButton"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"; Name="CanCortanaBeEnabled"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="ConnectedSearchUseWebOverMeteredConnections"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="AllowCortanaAboveLock"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings"; Name="IsDynamicSearchBoxEnabled"};
    @{Path="HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana"; Name="value"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"; Name="AllowSearchToUseLocation"};
    @{Path="HKCU:\Software\Microsoft\Speech_OneCore\Preferences"; Name="ModelDownloadAllowed"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings"; Name="IsDeviceSearchHistoryEnabled"};
    @{Path="HKCU:\Software\Microsoft\Speech_OneCore\Preferences"; Name="VoiceActivationOn"};
    @{Path="HKCU:\Software\Microsoft\Speech_OneCore\Preferences"; Name="VoiceActivationEnableAboveLockscreen"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"; Name="DisableVoice"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="AllowCortana"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"; Name="DeviceHistoryEnabled"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"; Name="HistoryViewEnabled"};
    @{Path="HKLM:\Software\Microsoft\Speech_OneCore\Preferences"; Name="VoiceActivationDefaultOn"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"; Name="CortanaEnabled"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"; Name="CortanaEnabled"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings"; Name="IsMSACloudSearchEnabled"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings"; Name="IsAADCloudSearchEnabled"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="AllowCloudSearch"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"; Name="VoiceShortcut"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"; Name="CortanaConsent"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Siuf\Rules"; Name="NumberOfSIUFInPeriod"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Siuf\Rules"; Name="PeriodInDays"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Siuf\Rules"; Name="NumberOfNotificationsSent"};
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name="DoNotShowFeedbackNotifications"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Name="DoNotShowFeedbackNotifications"};
    @{Path="HKCU:\Software\Policies\Microsoft\InputPersonalization"; Name="RestrictImplicitInkCollection"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"; Name="RestrictImplicitInkCollection"};
    @{Path="HKCU:\Software\Policies\Microsoft\InputPersonalization"; Name="RestrictImplicitTextCollection"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"; Name="RestrictImplicitTextCollection"};
    @{Path="HKCU:\Software\Policies\Microsoft\Windows\HandwritingErrorReports"; Name="PreventHandwritingErrorReports"};
    @{Path="HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports"; Name="PreventHandwritingErrorReports"};
    @{Path="HKCU:\Software\Policies\Microsoft\Windows\TabletPC"; Name="PreventHandwritingDataSharing"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"; Name="PreventHandwritingDataSharing"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"; Name="AllowInputPersonalization"};
    @{Path="HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"; Name="HarvestContacts"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Personalization\Settings"; Name="AcceptedPrivacyPolicy"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name="DisableSoftLanding"};
    @{Path="HKLM:\Software\Policies\Microsoft\Windows\CloudContent"; Name="DisableWindowsSpotlightFeatures"};
    @{Path="HKLM:\Software\Policies\Microsoft\Windows\CloudContent"; Name="DisableWindowsConsumerFeatures"};
    @{Path="HKCU:\Software\Policies\Microsoft\Windows\CloudContent"; Name="DisableTailoredExperiencesWithDiagnosticData"};
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"; Name="Enabled"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"; Name="DisabledByGroupPolicy"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-338393Enabled"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-353694Enabled"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-353696Enabled"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-338387Enabled"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-338388Enabled"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-338389Enabled"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-353698Enabled"};
    @{Path="HKLM:\SOFTWARE\NVIDIA Corporation\Global\NvTelemetry"; Name="Enabled"};
    @{Path="HKLM:\SOFTWARE\AMD\ACE\Settings\General"; Name="EnableTelemetry"};
    @{Path="HKLM:\SOFTWARE\Intel\Display\igfxcui\Telemetry"; Name="EnableTelemetry"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="MetricsReportingEnabled"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="BrowserSignin"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="ShoppingAssistantEnabled"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="PersonalizationReportingEnabled"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name="ShowRecommendationsEnabled"};
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR"; Name="AppCaptureEnabled"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"; Name="AllowGameDVR"};
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"; Name="DisableLocation"};
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"; Name="Status"}
)

$totalKeys = $registryKeysToBackup.Count
$processedKeys = 0
foreach ($keyInfo in $registryKeysToBackup) {
    $processedKeys++
    Write-Progress -Activity "Backing up Registry" -Status "Processing key $processedKeys of $totalKeys" -PercentComplete (($processedKeys / $totalKeys) * 100)
    $regBackupData += Get-RegistryValueBackup -Path $keyInfo.Path -Name $keyInfo.Name
}
Write-Host "Backed up $($regBackupData.Count) registry values."

#================================================================================
# SCRIPT COMPLETION - SAVING DATA
#================================================================================
Write-Host "--- Saving backup data to CSV files..." -ForegroundColor Green

if ($regBackupData.Count -gt 0) { $regBackupData | Export-Csv -Path $regBackupFile -NoTypeInformation -Encoding UTF8 }
if ($serviceBackupData.Count -gt 0) { $serviceBackupData | Export-Csv -Path $serviceBackupFile -NoTypeInformation -Encoding UTF8 }
if ($taskBackupData.Count -gt 0) { $taskBackupData | Export-Csv -Path $taskBackupFile -NoTypeInformation -Encoding UTF8 }
if ($envVarBackupData.Count -gt 0) { $envVarBackupData | Export-Csv -Path $envVarBackupFile -NoTypeInformation -Encoding UTF8 }

Write-Host ""
Write-Host "==============================================" -ForegroundColor Green
Write-Host "            BACKUP PROCESS COMPLETE           " -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green
Write-Host "All current settings have been saved to:"
Write-Host "$backupDir" -ForegroundColor Yellow
Write-Host "You can now safely run the telemetry.ps1 script."
Write-Host "Keep the 'telemetry-restore.ps1' script safe in case you need to revert changes."