# ==============================================
# R Y Z Ξ N Optimizer
# Version: 2.0 | Date: 2025-07-25
# ==============================================

#Requires -RunAsAdministrator

# ----------------------------
# Initial Setup
# ----------------------------
$Host.UI.RawUI.WindowTitle = "Ryzen Optimizer v2.0"
Clear-Host

Write-Host ""
Write-Host "==============================================" -ForegroundColor Green
Write-Host "            REMOVE UNWANTED APPS              " -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green

Write-Output "Disabling Recall Feature"
Dism /Online /Disable-Feature /Featurename:Recall /NoRestart

Write-Output "-- Uninstalling unwanted apps"

$packagesToRemove = @(
    # Third-party apps
    'king.com.CandyCrushSaga',
    'king.com.CandyCrushSodaSaga',
    'ShazamEntertainmentLtd.Shazam',
    'Flipboard.Flipboard',
    '9E2F88E3.Twitter',
    'ClearChannelRadioDigital.iHeartRadio',
    'D5EA27B7.Duolingo-LearnLanguagesforFree',
    'AdobeSystemsIncorporated.AdobePhotoshopExpress',
    'PandoraMediaInc.29680B314EFC2',
    '46928bounde.EclipseManager',
    'ActiproSoftwareLLC.562882FEEB491',

    # Extensions
    'Microsoft.HEIFImageExtension',
    'Microsoft.VP9VideoExtensions',
    'Microsoft.WebpImageExtension',
    'Microsoft.HEVCVideoExtension',
    'Microsoft.RawImageExtension',
    'Microsoft.WebMediaExtensions',

    # Microsoft apps
    'MicrosoftCorporationII.MicrosoftFamily',
    'Microsoft.OutlookForWindows',
    'Clipchamp.Clipchamp',
    'Microsoft.3DBuilder',
    'Microsoft.Microsoft3DViewer',
    'Microsoft.BingWeather',
    'Microsoft.BingSports',
    'Microsoft.BingTranslator',
    'Microsoft.BingTravel',
    'Microsoft.BingSearch',
    'Microsoft.MicrosoftJournal',
    'Microsoft.Windows.Ai.Copilot.Provider',
    'Microsoft.Copilot',
    'Microsoft.Copilot_8wekyb3d8bbwe',
    'Microsoft.QuickAssist',
    'Microsoft.PowerAutomateDesktop',
    'Microsoft.ZuneMusic',
    'Microsoft.ZuneVideo',
    'Microsoft.WindowsMeetNow',
    'Microsoft.Paint',
    'Microsoft.XboxGameBar',
    'Microsoft.GetHelp',
    'Microsoft.BingFinance',
    'Microsoft.MicrosoftOfficeHub',
    'Microsoft.WindowsTerminal',
    'Microsoft.BingNews',
    'Microsoft.News',
    'Microsoft.MicrosoftPowerBIForWindows',
    'Microsoft.Office.OneNote',
    'Microsoft.Office.Sway',
    'Microsoft.WindowsPhone',
    'Microsoft.CommsPhone',
    'Microsoft.YourPhone',
    'Microsoft.Getstarted',
    'Microsoft.549981C3F5F10',
    'Microsoft.Windows.DevHome',
    'Microsoft.Messaging',
    'Microsoft.NetworkSpeedTest',
    'Microsoft.WindowsSoundRecorder',
    'Microsoft.MixedReality.Portal',
    'Microsoft.WindowsFeedbackHub',
    'Microsoft.WindowsAlarms',
    'Microsoft.WindowsCamera',
    'Microsoft.MSPaint',
    'Microsoft.WindowsMaps',
    'Microsoft.MinecraftUWP',
    'Microsoft.People',
    'Microsoft.Wallet',
    'Microsoft.Print3D',
    'Microsoft.OneConnect',
    'Microsoft.MicrosoftSolitaireCollection',
    'Microsoft.MicrosoftStickyNotes',
    'microsoft.windowscommunicationsapps',
    'Microsoft.SkypeApp',
    'Microsoft.GroupMe10',
    'MSTeams',
    'Microsoft.Todos'
)

foreach ($pkg in $packagesToRemove) {
    $appxFound = $false
    $provFound = $false

    $installed = Get-AppxPackage -AllUsers | Where-Object { $_.Name -eq $pkg }
    if ($installed) {
        $appxFound = $true
        Write-Output "Removing: $pkg"
        $installed | ForEach-Object {
            Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction SilentlyContinue
        }
    }

    $provisioned = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $pkg }
    if ($provisioned) {
        $provFound = $true
        Write-Output "Removing provisioned package: $pkg"
        $provisioned | ForEach-Object {
            Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction SilentlyContinue
        }
    }

    if (-not $appxFound -and -not $provFound) {
        Write-Output "Not found: $pkg"
    }
}

Write-Output "-- Removing capabilities"

$capabilitiesToRemove = @(
    'App.Support.QuickAssist',
    'Browser.InternetExplorer',
    'MathRecognizer',
    'OpenSSH.Client',
    'Microsoft.Windows.MSPaint',
    'Microsoft.Windows.PowerShell.ISE',
    'App.StepsRecorder',
    'Media.WindowsMediaPlayer',
    'Microsoft.Windows.WordPad'
)

foreach ($cap in $capabilitiesToRemove) {
    Get-WindowsCapability -Online | Where-Object { $_.Name -like "$cap*" } | ForEach-Object {
        Write-Output "Removing capability: $($_.Name)"
        Remove-WindowsCapability -Online -Name $_.Name
    }
}

Write-Output "-- Disabling Copilot and Chat"

New-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search' -Force | Out-Null
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Search' -Name 'CortanaConsent' -Value 0 -Force

New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CloudContent' -Name 'TurnOffWindowsCopilot' -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowCopilotButton' -Value 0 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideNewOutlookToggle' -Value 0 -PropertyType DWord -Force | Out-Null

Write-Output "-- Removing WebExperience package"
Get-AppxPackage *WebExperience* | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
