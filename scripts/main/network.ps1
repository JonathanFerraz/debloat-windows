#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidateSet('Cloudflare', 'Google', 'Quad9', 'DHCP')]
    [string]$DnsProvider = 'Cloudflare',
    [switch]$BackupOnly,
    [string]$BackupDirectory
)

# Configure DNS here so registry.ps1 cannot overwrite the selected provider.
# Flushing the resolver cache does not require releasing DHCP leases.
$providers = @{
    Cloudflare = @('1.1.1.1', '1.0.0.1', '2606:4700:4700::1111', '2606:4700:4700::1001')
    Google = @('8.8.8.8', '8.8.4.4', '2001:4860:4860::8888', '2001:4860:4860::8844')
    # Quad9 is intentionally selectable, but filters malicious domains.
    Quad9 = @('9.9.9.9', '149.112.112.112', '2620:fe::fe', '2620:fe::9')
}
$adapters = @(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object Status -eq 'Up')
if (-not $adapters.Count) {
    if ($BackupOnly) { Write-Warning 'No active physical adapters to back up.'; return }
    throw 'No active physical network adapter found.'
}

# Record both address families and whether DNS was static before changing it.
$backupDir = if ($BackupDirectory) { $BackupDirectory } else { Join-Path "$env:SystemDrive\Ryzen Optimizer\Backup" ("network-" + (Get-Date -Format 'yyyy-MM-dd_HH-mm-ss-fff')) }
New-Item -ItemType Directory -Path $backupDir -ErrorAction Stop | Out-Null
$before = foreach ($adapter in $adapters) {
    foreach ($family in @('IPv4', 'IPv6')) {
        $stack = if ($family -eq 'IPv4') { 'Tcpip' } else { 'Tcpip6' }
        $guid = ([guid]$adapter.InterfaceGuid).ToString('B')
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$stack\Parameters\Interfaces\$guid"
        $static = if (Test-Path -LiteralPath $key -ErrorAction Stop) { (Get-ItemProperty -LiteralPath $key -ErrorAction Stop).NameServer } else { $null }
        [pscustomobject]@{
            InterfaceGuid = $guid
            AddressFamily = $family
            Static = -not [string]::IsNullOrWhiteSpace($static)
            ServerAddresses = @((Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily $family -ErrorAction Stop).ServerAddresses)
        }
    }
}
$before | Export-Clixml -LiteralPath (Join-Path $backupDir 'dns.xml') -ErrorAction Stop
& netsh.exe int tcp show global | Set-Content -LiteralPath (Join-Path $backupDir 'tcp-before.txt') -ErrorAction Stop
if ($LASTEXITCODE -ne 0) { throw 'Could not capture TCP settings.' }
if ($BackupOnly) { Write-Host "Network backup: $backupDir"; return }

foreach ($adapter in $adapters) {
    if ($DnsProvider -eq 'DHCP') {
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses -ErrorAction Stop
    } else {
        Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $providers[$DnsProvider] -ErrorAction Stop
    }
    Write-Host "DNS on $($adapter.Name): $DnsProvider"
}
& netsh.exe int tcp set global autotuninglevel=normal
if ($LASTEXITCODE -ne 0) { throw 'Could not enable normal TCP receive-window auto-tuning.' }
Clear-DnsClientCache -ErrorAction Stop
Write-Host "Network settings applied. Previous settings: $backupDir"
