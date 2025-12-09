#Requires -RunAsAdministrator

Clear-Host
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host "         BACKUP SCRIPT FOR SERVICES           " -ForegroundColor Yellow
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host ""

# --- Initial Setup and Admin Check ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script must be run as Administrator."
    Start-Sleep -Seconds 10
    exit
}

# --- Backup Directory Configuration ---
$backupBaseDir = "C:\Ryzen Optimizer\Backup"
$timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$folderName = "services-$timestamp"
$backupDir = Join-Path -Path $backupBaseDir -ChildPath $folderName
New-Item -Path $backupDir -ItemType Directory -Force | Out-Null

$backupFile = Join-Path $backupDir "services-backup.csv"
Write-Host "Generating backup..."
Write-Host "Backup will be saved to: $backupFile" -ForegroundColor Cyan

# --- List of Services to Backup ---
$serviceNames = @(
    "AJRouter", "ALG", "AMD Crash Defender Service", "AMDLinkAgent", "AMDCrashDefender",
    "AppVClient", "AssignedAccessManagerSvc", "AsusUpdateCheck", "BDESVC", "BITS", "BTAGService",
    "bthserv", "BthAvctpSvc", "CDPSvc", "CertPropSvc", "CscService", "DiagTrack", "diagsvc",
    "DialogBlockingService", "dmwappushservice", "DPS", "Fax", "FrameServer", "icssvc", "lfsvc",
    "lmhosts", "LMS", "NvTelemetryContainer", "NvTelemetryNetworkService", "NvContainerLocalSystem",
    "NvContainerNetworkService", "MapsBroker", "MSDTC", "Netlogon", "NetTcpPortSharing", "PcaSvc",
    "PhoneSvc", "pla", "RasAuto", "RasMan", "RemoteAccess", "RemoteRegistry", "RetailDemo",
    "SCardSvr", "ScDeviceEnum", "SCPolicySvc", "seclogon", "SensorService", "SessionEnv",
    "shpamsvc", "Spooler", "StiSvc", "SysMain", "TabletInputService", "TapiSrv", "TermService",
    "tzautoupdate", "UevAgentService", "UmRdpService", "UsoSvc", "WalletService", "WbioSrvc",
    "WdiServiceHost", "WdiSystemHost", "WerSvc", "wisvc", "workfolderssvc", "WpcMonSvc", "WSearch",
    "wuauserv", "AppMgmt", "AppReadiness", "Appinfo", "AxInstSV", "BcastDVRUserService",
    "BluetoothUserService", "Browser", "COMSysApp", "CaptureService", "ClipSVC",
    "ConsentUxUserSvc", "DevQueryBroker", "DeviceAssociationService", "DeviceInstall",
    "DevicePickerUserSvc", "DevicesFlowUserSvc", "DisplayEnhancementService", "DmEnrollmentSvc",
    "DsSvc", "DsmSvc", "EFS", "EapHost", "EntAppSvc", "FDResPub", "FrameServerMonitor",
    "GraphicsPerfSvc", "HvHost", "IEEtwCollectorService", "InstallService", "InventorySvc",
    "IpxlatCfgSvc", "KtmRm", "LicenseManager", "LxpSvc", "MSiSCSI", "McpManagementService",
    "MessagingService", "MsKeyboardFilter", "NPSMSvc", "NaturalAuthentication", "NcaSvc",
    "NcbService", "NcdAutoSetup", "NetSetupSvc", "Netman", "NgcCtnrSvc", "NgcSvc", "NlaSvc",
    "P9RdrService", "PNRPAutoReg", "PNRPsvc", "PeerDistSvc", "PenService", "PerfHost",
    "PimIndexMaintenanceSvc", "PlugPlay", "PolicyAgent", "PrintNotify", "PushToInstall", "QWAVE",
    "RmSvc", "RpcLocator", "SDRSVC", "SEMgrSvc", "SNMPTRAP", "SNMPTrap", "SSDPSRV",
    "SensorDataService", "SensrSvc", "SharedAccess", "SmsRouter", "SstpSvc", "StateRepository",
    "StorSvc", "TextInputManagementService", "TieringEngineService", "TokenBroker",
    "TroubleshootingSvc", "TrustedInstaller", "UdkUserSvc", "UnistoreSvc", "UserDataSvc", "VSS",
    "VacSvc", "WEPHOSTSVC", "WFDSConMgrSvc", "WMPNetworkSvc", "WManSvc", "WPDBusEnum",
    "WarpJITSvc", "WdNisSvc", "WebClient", "Wecsvc", "WiaRpc", "WinHttpAutoProxySvc", "WinRM",
    "WpnService", "WwanSvc", "autotimesvc", "camsvc", "cbdhsvc", "cloudidsvc", "dcsvc",
    "defragsvc", "diagnosticshub.standardcollector.service", "dot3svc", "embeddedmode", "fdPHost",
    "fhsvc", "hidserv", "lltdsvc", "msiserver", "netprofm", "p2pimsvc", "p2psvc",
    "perceptionsimulation", "smphost", "ssh-agent", "svsvc", "swprv", "upnphost", "vds",
    "vmicguestinterface", "vmicheartbeat", "vmickvpexchange", "vmicrdv", "vmicshutdown",
    "vmictimesync", "vmicvmsession", "vmicvss", "vmvss", "wbengine", "wcncsvc",
    "webthreatdefsvc", "wercplsupport", "wlidsvc", "wlpasvc", "wmiApSrv", "wudfsvc"
)

# --- Data Collection and Export ---
# Collect all service data into an array first for better performance and reliability
$backupData = @()

foreach ($serviceName in $serviceNames) {
    try {
        $service = Get-Service -Name $serviceName -ErrorAction Stop
        # WMI is used for StartMode as it's more reliable than Get-Service's StartType for some services
        $startType = (Get-WmiObject -Class Win32_Service -Filter "Name='$($service.Name)'" | Select-Object -ExpandProperty StartMode)
        
        $backupData += [PSCustomObject]@{
            Name      = $service.Name
            Status    = $service.Status
            StartType = $startType
        }
    } catch {
        # Service not found, do nothing and do not show error
    }
}

if ($backupData.Count -gt 0) {
    $backupData | Export-Csv -Path $backupFile -NoTypeInformation -Encoding UTF8
    Write-Host ""
    Write-Host "Backup process complete!" -ForegroundColor Green
    Write-Host "$($backupData.Count) services were backed up successfully."
} else {
    Write-Warning "No services from the list were found on this system. Backup file was not created."
}