#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][string]$BackupDirectory)

$ErrorActionPreference = 'Stop'
$entries = @(Import-Clixml -LiteralPath (Join-Path $BackupDirectory 'dns.xml'))
$adapters = @(Get-NetAdapter -ErrorAction Stop)
foreach ($entry in $entries) {
    if ($entry.AddressFamily -notin @('IPv4', 'IPv6') -or $entry.Static -isnot [bool]) { throw 'Invalid DNS backup.' }
    $guid = [guid]$entry.InterfaceGuid
    $adapter = $adapters | Where-Object { [guid]$_.InterfaceGuid -eq $guid } | Select-Object -First 1
    if (-not $adapter) { Write-Warning "Adapter $($entry.InterfaceGuid) is no longer present."; continue }
    if ($entry.Static) {
        if (-not @($entry.ServerAddresses).Count) { throw 'Static DNS backup has no addresses.' }
        foreach ($address in $entry.ServerAddresses) { [void][System.Net.IPAddress]::Parse($address) }
    }
    if ($PSCmdlet.ShouldProcess("$($adapter.Name) / $($entry.AddressFamily)", 'Restore previous DNS mode and addresses')) {
        $dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily $entry.AddressFamily -ErrorAction Stop
        if ($entry.Static) { $dns | Set-DnsClientServerAddress -ServerAddresses $entry.ServerAddresses -ErrorAction Stop }
        else { $dns | Set-DnsClientServerAddress -ResetServerAddresses -ErrorAction Stop }
    }
}
Write-Host 'DNS restore finished. Previous TCP settings are recorded in tcp-before.txt for reference.'
