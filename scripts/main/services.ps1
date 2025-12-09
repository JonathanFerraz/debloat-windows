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

# Backup services before making changes
& "$PSScriptRoot\..\backup\services-backup.ps1"

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
    "BITS",
    # "BTAGService",
    # "bthserv",
    # "BthAvctpSvc",
    # "CDPSvc",
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
    "SysMain",
    "TabletInputService",
    "TapiSrv",
    "TermService",
    "tzautoupdate",
    "UevAgentService",
    "UmRdpService",
    "UsoSvc",
    "WalletService",
    "WbioSrvc",
    "WdiServiceHost",
    "WdiSystemHost",
    "WerSvc",
    "wisvc",
    "workfolderssvc",
    "WpcMonSvc",
    "WSearch",
    "wuauserv"
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

# Section 1: Stop and Disable Services

Write-Host "Starting service stop and disable process..."
Write-Host "---------------------------------------------------------"

foreach ($serviceName in $ServicesToStopAndDisable) {
    try {
        # Attempt to get the service
        $service = Get-Service -Name $serviceName -ErrorAction Stop

        Write-Host "Processing '$($service.DisplayName)' (Service Name: $serviceName)..."

        # 1. Stop the service
        if ($service.Status -eq "Running") {
            Write-Host "  Stopping the service..." -NoNewline
            Stop-Service -InputObject $service -Force -ErrorAction Stop
            Write-Host " Done."
        }
        else {
            Write-Host "  Service is already stopped."
        }

        # 2. Disable the service
        if ($service.StartType -ne "Disabled") {
            Write-Host "  Disabling the service..." -NoNewline
            Set-Service -InputObject $service -StartupType Disabled -ErrorAction Stop
            Write-Host " Done."
        }
        else {
            Write-Host "  Service is already disabled."
        }

        Write-Host "  '$($service.DisplayName)' - Stopped and disabled successfully."
        Write-Host "" # Blank line for better readability

    }
    catch {
        Write-Warning "  Error processing '$serviceName' for stop/disable: $($_.Exception.Message)"
        Write-Warning "  The service might not exist or you might not have permissions."
        Write-Host "" # Blank line for better readability
    }
}

Write-Host "---------------------------------------------------------"
Write-Host "Service stop and disable process completed."
Write-Host "" # Blank line to separate sections

# Section 2: Set Services to Manual (Demand) Startup Type

Write-Host "Starting process to set services to Manual (Demand) Startup Type..."
Write-Host "-----------------------------------------------------------------------------------"

foreach ($serviceName in $ServicesToSetManual) {
    try {
        # Attempt to get the service
        $service = Get-Service -Name $serviceName -ErrorAction Stop

        Write-Host "Configuring '$($service.DisplayName)' (Service Name: $serviceName)..."

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
        Write-Host "" # Blank line for better readability

    }
    catch {
        Write-Warning "  Error processing '$serviceName' for 'Manual' startup type: $($_.Exception.Message)"
        Write-Warning "  The service might not exist or you might not have permissions."
        Write-Host "" # Blank line for better readability
    }
}

Write-Host "-----------------------------------------------------------------------------------"
Write-Host "Service configuration to Manual (Demand) Startup Type completed."
