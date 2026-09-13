#Requires -RunAsAdministrator
[CmdletBinding()]
param([ValidateRange(1, 90)][int]$Days = 14)

$ErrorActionPreference = 'Stop'
$directory = Join-Path "$env:SystemDrive\Ryzen Optimizer\Diagnostics" (Get-Date -Format 'yyyy-MM-dd_HH-mm-ss-fff')
New-Item -ItemType Directory -Path $directory -ErrorAction Stop | Out-Null
$since = (Get-Date).AddDays(-$Days)
# Local collection only; no uploads, event deletion or automatic restarts.
foreach ($log in @('System', 'Application')) {
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $since; Level = @(1, 2, 3) } -MaxEvents 3000 -ErrorAction SilentlyContinue)
    $events | Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message |
        Export-Csv -LiteralPath (Join-Path $directory "$log.csv") -NoTypeInformation -Encoding UTF8
    $events | ForEach-Object { $_.ToXml() } | Set-Content -LiteralPath (Join-Path $directory "$log-event-xml.txt") -Encoding UTF8
}
Get-WinEvent -FilterHashtable @{LogName='System'; Id=@(41, 1001, 1074, 6008); StartTime=$since} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, ProviderName, Message | Export-Csv -LiteralPath (Join-Path $directory 'restarts.csv') -NoTypeInformation -Encoding UTF8
foreach ($class in @('Win32_OperatingSystem', 'Win32_Processor', 'Win32_VideoController', 'Win32_PhysicalMemory')) {
    Get-CimInstance $class | Format-List * | Out-File -LiteralPath (Join-Path $directory "$class.txt") -Encoding UTF8
}
Get-NetAdapter | Format-List Name, InterfaceDescription, Status, LinkSpeed, DriverVersion |
    Out-File -LiteralPath (Join-Path $directory 'adapters.txt') -Encoding UTF8
Get-DnsClientServerAddress | Format-List | Out-File -LiteralPath (Join-Path $directory 'dns.txt') -Encoding UTF8
& netsh.exe int tcp show global | Out-File -LiteralPath (Join-Path $directory 'tcp.txt') -Encoding UTF8
& powercfg.exe /getactivescheme | Out-File -LiteralPath (Join-Path $directory 'power-plan.txt') -Encoding UTF8
& bcdedit.exe /enum '{current}' | Out-File -LiteralPath (Join-Path $directory 'boot.txt') -Encoding UTF8
Get-PnpDevice -Class System | Where-Object Status -ne 'OK' | Format-List |
    Out-File -LiteralPath (Join-Path $directory 'system-devices.txt') -Encoding UTF8
Get-ChildItem "$env:windir\Minidump", "$env:windir\LiveKernelReports" -Recurse -File -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, LastWriteTime | Export-Csv -LiteralPath (Join-Path $directory 'dump-files.csv') -NoTypeInformation -Encoding UTF8
Write-Host "Diagnostics saved locally: $directory"
Write-Host 'Event 41 records an unclean restart; it does not identify the cause by itself. Review before sharing.'
