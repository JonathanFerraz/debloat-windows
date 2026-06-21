# ==============================================
# R Y Z Ξ N Optimizer
# Version: 3.0 | Date: 2025-07-25
# ==============================================

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$DisableXboxLoginFeatures,
    [switch]$SkipBackup
)

# ----------------------------
# Initial Setup
# ----------------------------
$Host.UI.RawUI.WindowTitle = "Ryzen Optimizer v3.0"
Clear-Host

# Import shared module
Import-Module "$PSScriptRoot\..\lib\RyzenOptimizer.psm1" -Force -ErrorAction Stop

# Backup services before making changes
if (-not $SkipBackup) {
    & "$PSScriptRoot\..\backup\services-backup.ps1"
}

Write-Host ""
Write-Host "==============================================" -ForegroundColor Green
Write-Host "          DISABLE UNWANTED SERVICES           " -ForegroundColor Green
Write-Host "==============================================" -ForegroundColor Green

# List of service names to stop and disable
$ServicesToStopAndDisable = @(
    "AJRouter",
    "ALG",
    "AMD Crash Defender Service",
    "AMDLinkAgent",
    "AMDCrashDefender",
    "AppVClient",
    "AssignedAccessManagerSvc",
    "AsusUpdateCheck",
    "BDESVC",
    "CertPropSvc",
    "CscService",
    "DiagTrack",
    "diagsvc",
    "DialogBlockingService",
    "dmwappushservice",
    "DPS",
    "Fax",
    "FrameServer",
    "icssvc",
    "lfsvc",
    "lmhosts",
    "LMS",
    "NvTelemetryContainer",
    "NvTelemetryNetworkService",
    "NvContainerLocalSystem",
    "NvContainerNetworkService",
    "MapsBroker",
    "MSDTC",
    "Netlogon",
    "NetTcpPortSharing",
    "PcaSvc",
    "PhoneSvc",
    "pla",
    "RasAuto",
    "RasMan",
    "RemoteAccess",
    "RemoteRegistry",
    "RetailDemo",
    "SCardSvr",
    "ScDeviceEnum",
    "SCPolicySvc",
    "seclogon",
    "SensorService",
    "SessionEnv",
    "shpamsvc",
    "Spooler",
    "StiSvc",
    "TabletInputService",
    "TapiSrv",
    "TermService",
    "tzautoupdate",
    "UevAgentService",
    "UmRdpService",
    "WalletService",
    "WbioSrvc",
    "WdiServiceHost",
    "WdiSystemHost",
    "WerSvc",
    "wisvc",
    "workfolderssvc",
    "WpcMonSvc",
    "WSearch"
)

# List of service names to set to 'Manual' (Demand) startup type
$ServicesToSetManual = @(
    "AppMgmt",
    "AppReadiness",
    "Appinfo",
    "AxInstSV",
    "BcastDVRUserService",
    "BluetoothUserService",
    "Browser",
    "COMSysApp",
    "CaptureService",
    "ClipSVC",
    "ConsentUxUserSvc",
    "DevQueryBroker",
    "DeviceAssociationService",
    "DeviceInstall",
    "DevicePickerUserSvc",
    "DevicesFlowUserSvc",
    "DisplayEnhancementService",
    "DmEnrollmentSvc",
    "DsSvc",
    "DsmSvc",
    "EFS",
    "EapHost",
    "EntAppSvc",
    "FDResPub",
    "FrameServerMonitor",
    "GraphicsPerfSvc",
    "HvHost",
    "IEEtwCollectorService",
    "InstallService",
    "InventorySvc",
    "IpxlatCfgSvc",
    "KtmRm",
    "LicenseManager",
    "LxpSvc",
    "MSiSCSI",
    "McpManagementService",
    "MessagingService",
    "MsKeyboardFilter",
    "NPSMSvc",
    "NaturalAuthentication",
    "NcaSvc",
    "NcbService",
    "NcdAutoSetup",
    "NetSetupSvc",
    "Netman",
    "NgcCtnrSvc",
    "NgcSvc",
    "NlaSvc",
    "P9RdrService",
    "PNRPAutoReg",
    "PNRPsvc",
    "PeerDistSvc",
    "PenService",
    "PerfHost",
    "PimIndexMaintenanceSvc",
    "PlugPlay",
    "PolicyAgent",
    "PrintNotify",
    "PushToInstall",
    "QWAVE",
    "RmSvc",
    "RpcLocator",
    "SDRSVC",
    "SEMgrSvc",
    "SNMPTRAP",
    "SNMPTrap",
    "SSDPSRV",
    "SensorDataService",
    "SensrSvc",
    "SharedAccess",
    "SmsRouter",
    "SstpSvc",
    "StateRepository",
    "SysMain",
    "StorSvc",
    "TextInputManagementService",
    "TieringEngineService",
    "TokenBroker",
    "TroubleshootingSvc",
    "TrustedInstaller",
    "UdkUserSvc",
    "UnistoreSvc",
    "UserDataSvc",
    "VSS",
    "VacSvc",
    "WEPHOSTSVC",
    "WFDSConMgrSvc",
    "WMPNetworkSvc",
    "WManSvc",
    "WPDBusEnum",
    "WarpJITSvc",
    "WdNisSvc",
    "WebClient",
    "Wecsvc",
    "WiaRpc",
    "WinHttpAutoProxySvc",
    "WinRM",
    "WpnService",
    "WwanSvc",
    "autotimesvc",
    "camsvc",
    "cbdhsvc",
    "cloudidsvc",
    "dcsvc",
    "defragsvc",
    "diagnosticshub.standardcollector.service",
    "dot3svc",
    "embeddedmode",
    "fdPHost",
    "fhsvc",
    "hidserv",
    "lltdsvc",
    "msiserver",
    "netprofm",
    "p2pimsvc",
    "p2psvc",
    "perceptionsimulation",
    "smphost",
    "ssh-agent",
    "svsvc",
    "swprv",
    "upnphost",
    "vds",
    "vmicguestinterface",
    "vmicheartbeat",
    "vmickvpexchange",
    "vmicrdv",
    "vmicshutdown",
    "vmictimesync",
    "vmicvmsession",
    "vmicvss",
    "vmvss",
    "wbengine",
    "wcncsvc",
    "webthreatdefsvc",
    "wercplsupport",
    "wlidsvc",
    "wlpasvc",
    "wmiApSrv",
    "wudfsvc"
)

# Helper: resolve service names, including per-user services (Name_XXXX pattern)
function Resolve-ServiceObjects {
    param([string]$ServiceName)

    $resolved = @()

    $exact = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($exact) {
        $resolved += $exact
    }
    else {
        $resolved += Get-Service -Name "$ServiceName`_*" -ErrorAction SilentlyContinue
    }

    return $resolved | Sort-Object -Property Name -Unique
}

# Section 1: Stop and Disable Services

Write-Host "Starting service stop and disable process..."
Write-Host "---------------------------------------------------------"

foreach ($serviceName in ($ServicesToStopAndDisable | Select-Object -Unique)) {
    $services = Resolve-ServiceObjects -ServiceName $serviceName
    if (-not $services) {
        Write-Host "Skipping '$serviceName' (service not found on this system)." -ForegroundColor DarkYellow
        Write-Host ""
        continue
    }

    foreach ($service in $services) {
        try {
            Write-Host "Processing '$($service.DisplayName)' (Service Name: $($service.Name))..."

            # 1. Disable the service FIRST (so it won't restart)
            if ($service.StartType -ne "Disabled") {
                Write-Host "  Disabling the service..." -NoNewline
                Set-Service -InputObject $service -StartupType Disabled -ErrorAction Stop
                Write-Host " Done."
            }
            else {
                Write-Host "  Service is already disabled."
            }

            # 2. Stop the service with timeout (max 10 seconds)
            if ($service.Status -eq "Running") {
                Write-Host "  Stopping the service (timeout 10s)..." -NoNewline
                $stopJob = Start-Job -ScriptBlock {
                    param($svcName)
                    Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
                } -ArgumentList $service.Name
                $completed = Wait-Job $stopJob -Timeout 10
                if ($completed) {
                    Receive-Job $stopJob -ErrorAction SilentlyContinue | Out-Null
                    Write-Host " Done."
                } else {
                    Stop-Job $stopJob -ErrorAction SilentlyContinue
                    # Fallback: try taskkill
                    $svcPID = (Get-CimInstance Win32_Service -Filter "Name='$($service.Name)'" -ErrorAction SilentlyContinue).ProcessId
                    if ($svcPID -and $svcPID -ne 0) {
                        taskkill /F /PID $svcPID 2>$null | Out-Null
                    }
                    Write-Host " Timed out (will stop on reboot)."
                }
                Remove-Job $stopJob -Force -ErrorAction SilentlyContinue
            }
            else {
                Write-Host "  Service is already stopped."
            }

            Write-Host "  '$($service.DisplayName)' - Processed successfully."
            Write-Host ""
        }
        catch {
            Write-Warning "  Error processing '$($service.Name)' for stop/disable: $($_.Exception.Message)"
            Write-Host ""
        }
    }
}

Write-Host "---------------------------------------------------------"
Write-Host "Service stop and disable process completed."
Write-Host "" # Blank line to separate sections

# Section 2: Set Services to Manual (Demand) Startup Type

Write-Host "Starting process to set services to Manual (Demand) Startup Type..."
Write-Host "-----------------------------------------------------------------------------------"

foreach ($serviceName in ($ServicesToSetManual | Select-Object -Unique)) {
    $services = Resolve-ServiceObjects -ServiceName $serviceName
    if (-not $services) {
        Write-Host "Skipping '$serviceName' (service not found on this system)." -ForegroundColor DarkYellow
        Write-Host ""
        continue
    }

    foreach ($service in $services) {
        try {
            Write-Host "Configuring '$($service.DisplayName)' (Service Name: $($service.Name))..."

            # Check if the startup type is already 'Manual' (Demand)
            if ($service.StartType -ne "Manual") {
                # Note: If the service is running, it won't be stopped automatically when changing to manual,
                # but it won't start on the next system boot.
                Write-Host "  Setting startup type to 'Manual'..." -NoNewline
                Set-Service -InputObject $service -StartupType Manual -ErrorAction Stop
                Write-Host " Done."
            }
            else {
                Write-Host "  Service is already configured for 'Manual'."
            }

            Write-Host "  '$($service.DisplayName)' - Startup type set to 'Manual'."
            Write-Host ""
        }
        catch {
            Write-Warning "  Error processing '$($service.Name)' for 'Manual' startup type: $($_.Exception.Message)"
            Write-Host ""
        }
    }
}

Write-Host "-----------------------------------------------------------------------------------"
Write-Host "Service configuration to Manual (Demand) Startup Type completed."

# Section 3: Xbox login profile

Write-Host ""

if ($DisableXboxLoginFeatures) {
    Write-Host "Applying Xbox login debloat service profile..." -ForegroundColor Yellow

    $XboxServicesToDisable = @(
        "XblAuthManager",
        "XblGameSave",
        "XboxNetApiSvc",
        "GamingServices",
        "GamingServicesNet"
    )

    foreach ($serviceName in $XboxServicesToDisable) {
        try {
            $svc = Get-Service -Name $serviceName -ErrorAction Stop
            if ($svc.Status -eq "Running") {
                Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            }
            Set-Service -Name $serviceName -StartupType Disabled -ErrorAction Stop
            Write-Host "  '$serviceName' configured as 'Disabled'." -ForegroundColor Green
        }
        catch {
            Write-Host "  '$serviceName' not found on this system. Skipping." -ForegroundColor Yellow
        }
    }

    Write-Host "Xbox login debloat profile applied." -ForegroundColor Yellow
}
else {
    Write-Host "Applying Xbox/Microsoft sign-in compatibility service profile..." -ForegroundColor Cyan

    $CriticalAuthServices = @(
        @{ Name = "AppXSVC"; StartupType = "Manual"; StartNow = $false },
        @{ Name = "ClipSVC"; StartupType = "Manual"; StartNow = $true },
        @{ Name = "wlidsvc"; StartupType = "Manual"; StartNow = $true },
        @{ Name = "TokenBroker"; StartupType = "Manual"; StartNow = $false },
        @{ Name = "InstallService"; StartupType = "Manual"; StartNow = $false },
        @{ Name = "XblAuthManager"; StartupType = "Manual"; StartNow = $true },
        @{ Name = "XblGameSave"; StartupType = "Manual"; StartNow = $true },
        @{ Name = "XboxNetApiSvc"; StartupType = "Manual"; StartNow = $true },
        @{ Name = "GamingServices"; StartupType = "Automatic"; StartNow = $true },
        @{ Name = "GamingServicesNet"; StartupType = "Manual"; StartNow = $true }
    )

    foreach ($entry in $CriticalAuthServices) {
        try {
            $svc = Get-Service -Name $entry.Name -ErrorAction Stop
            Set-Service -Name $entry.Name -StartupType $entry.StartupType -ErrorAction Stop

            if ($entry.StartNow -and $svc.Status -ne "Running") {
                Start-Service -Name $entry.Name -ErrorAction SilentlyContinue
            }

            Write-Host "  '$($entry.Name)' configured as '$($entry.StartupType)'." -ForegroundColor Green
        }
        catch {
            Write-Host "  '$($entry.Name)' not found on this system. Skipping." -ForegroundColor Yellow
        }
    }

    Write-Host "Xbox/Microsoft sign-in compatibility profile applied." -ForegroundColor Cyan
}
