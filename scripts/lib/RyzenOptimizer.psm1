<#
.SYNOPSIS
    R Y Z E N Optimizer - Shared Module v3.0
.DESCRIPTION
    Unified helper functions for all Ryzen Optimizer scripts.
    Import with: Import-Module "$PSScriptRoot\..\lib\RyzenOptimizer.psm1"
#>

# -- Counters --
$script:Counters = @{
    RegistrySuccess = 0
    RegistryFail    = 0
    ServiceSuccess  = 0
    ServiceFail     = 0
    TaskSuccess     = 0
    TaskFail        = 0
}

function Get-OptimizerCounters { return $script:Counters }
function Reset-OptimizerCounters {
    $script:Counters.Keys | ForEach-Object { $script:Counters[$_] = 0 }
}

# -- Logging --
function Write-Step {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Info','Success','Warning','Error','Header','SubHeader')]
        [string]$Level = 'Info'
    )
    switch ($Level) {
        'Header'    { Write-Host "`n$Message" -ForegroundColor Green }
        'SubHeader' { Write-Host "$Message" -ForegroundColor Cyan }
        'Success'   { Write-Host "  [OK] $Message" -ForegroundColor Green }
        'Warning'   { Write-Host "  [!] $Message" -ForegroundColor Yellow }
        'Error'     { Write-Host "  [X] $Message" -ForegroundColor Red }
        default     { Write-Host "  $Message" -ForegroundColor White }
    }
}

function Show-Progress {
    param(
        [Parameter(Mandatory)][int]$Current,
        [Parameter(Mandatory)][int]$Total,
        [string]$Activity = 'Processing'
    )
    if ($Total -le 0) { return }
    $percent = [math]::Round(($Current / $Total) * 100)
    $barLen = 30
    $filled = [math]::Round($barLen * $Current / $Total)
    $empty  = $barLen - $filled
    $bar = ('#' * $filled) + ('-' * $empty)
    Write-Host ("`r  [$bar] $percent% - $Activity") -NoNewline -ForegroundColor Cyan
    if ($Current -eq $Total) { Write-Host '' }
}

# -- Registry --
function Set-RegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [string]$Type = 'DWord',
        [switch]$Force
    )
    try {
        if (!(Test-Path $Path)) {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }
        $psType = switch ($Type.ToUpper()) {
            'REG_DWORD'      { 'DWord' }
            'REG_SZ'         { 'String' }
            'REG_QWORD'      { 'QWord' }
            'REG_EXPAND_SZ'  { 'ExpandString' }
            'REG_MULTI_SZ'   { 'MultiString' }
            'REG_BINARY'     { 'Binary' }
            'DWORD'          { 'DWord' }
            'STRING'         { 'String' }
            'QWORD'          { 'QWord' }
            'EXPANDSTRING'   { 'ExpandString' }
            'MULTISTRING'    { 'MultiString' }
            'BINARY'         { 'Binary' }
            default          { $Type }
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $psType -Force -ErrorAction Stop
        $script:Counters.RegistrySuccess++
        return $true
    }
    catch {
        Write-Warning "Failed to set registry value: $Path\$Name - $($_.Exception.Message)"
        $script:Counters.RegistryFail++
        return $false
    }
}

function Remove-RegistryItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Name = $null,
        [switch]$Recurse
    )
    try {
        if (Test-Path $Path) {
            if ($Name) { Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction Stop }
            else       { Remove-Item -Path $Path -Force -Recurse:$Recurse -ErrorAction Stop }
            $script:Counters.RegistrySuccess++
            return $true
        }
        return $false
    }
    catch {
        Write-Verbose "Failed to remove registry item: $Path - $($_.Exception.Message)"
        $script:Counters.RegistryFail++
        return $false
    }
}

function Remove-RegistryProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )
    if (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue) {
        try {
            Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction Stop
            $script:Counters.RegistrySuccess++
            return $true
        }
        catch {
            $script:Counters.RegistryFail++
            return $false
        }
    }
    return $false
}

# -- Scheduled Tasks --
function Get-ScheduledTaskByReference {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Reference)
    $separator = $Reference.LastIndexOf('\')
    $taskPath = if ($separator -ge 0) { $Reference.Substring(0, $separator + 1) } else { '\' }
    $taskName = if ($separator -ge 0) { $Reference.Substring($separator + 1) } else { $Reference }
    if (-not $taskName) { $taskName = '*' }
    Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue
}

function Set-ScheduledTaskState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TaskName,
        [Parameter(Mandatory)][ValidateSet('Enable','Disable')][string]$Action
    )
    $tasks = @(Get-ScheduledTaskByReference -Reference $TaskName)
    if (-not $tasks.Count) { Write-Verbose "Task not found: $TaskName"; return $false }
    $success = $true
    foreach ($task in $tasks) {
        try {
            if ($Action -eq 'Enable') {
                $task | Enable-ScheduledTask -ErrorAction Stop | Out-Null
            } else {
                if ($task.State -eq 'Running') { $task | Stop-ScheduledTask -ErrorAction Stop }
                $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null
            }
            $script:Counters.TaskSuccess++
        } catch {
            $script:Counters.TaskFail++
            Write-Warning "Failed to $Action task $($task.TaskPath)$($task.TaskName): $($_.Exception.Message)"
            $success = $false
        }
    }
    return $success
}

function Disable-ScheduledTasksByPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$TaskPaths)
    foreach ($reference in ($TaskPaths | Select-Object -Unique)) {
        Set-ScheduledTaskState -TaskName $reference -Action Disable | Out-Null
    }
}

function Disable-TasksByRegex {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Regex)
    try {
        Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object { $_.TaskName -match $Regex -or $_.TaskPath -match $Regex } |
            ForEach-Object {
                try {
                    if ($_.State -ne 'Disabled') { $_ | Disable-ScheduledTask -ErrorAction Stop | Out-Null }
                    $script:Counters.TaskSuccess++
                } catch { $script:Counters.TaskFail++; Write-Warning "Failed to disable task $($_.Exception.Message)" }
            }
    } catch { }
}

# -- Services --
function Set-ServiceSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Disabled','Manual','Automatic')][string]$StartupType,
        [switch]$StopIfRunning
    )
    try {
        $svc = Get-Service -Name $Name -ErrorAction Stop
        if ($StopIfRunning -and $svc.Status -eq 'Running') {
            Stop-Service -Name $Name -Force -ErrorAction Stop
        }
        Set-Service -Name $Name -StartupType $StartupType -ErrorAction Stop
        $script:Counters.ServiceSuccess++
        Write-Host "Service '$Name' => $StartupType"
        return $true
    }
    catch {
        $script:Counters.ServiceFail++
        Write-Warning "Could not configure service '$Name': $($_.Exception.Message)"
        return $false
    }
}

function Set-ServiceState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$ServiceNames,
        [Parameter(Mandatory)][ValidateSet('Disabled','Automatic','Manual')][string]$StartupType,
        [ValidateSet('Stopped','Running','Unchanged')][string]$Status = 'Stopped'
    )
    foreach ($service in $ServiceNames) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc) {
            try {
                Set-Service -Name $service -StartupType $StartupType -ErrorAction Stop
                if ($Status -eq 'Stopped' -and $svc.Status -ne 'Stopped') { Stop-Service -Name $service -Force -ErrorAction Stop }
                elseif ($Status -eq 'Running' -and $svc.Status -ne 'Running') { Start-Service -Name $service -ErrorAction Stop }
                $script:Counters.ServiceSuccess++
            } catch { $script:Counters.ServiceFail++; Write-Warning "Could not configure service '$service': $($_.Exception.Message)" }
        }
    }
}

# -- BCDEdit --
function Invoke-BcdEdit {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Arguments)
    try {
        Invoke-Expression "bcdedit.exe $Arguments" 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "BCDEdit exit code: $LASTEXITCODE" }
        return $true
    }
    catch { return $false }
}

# -- System Detection --
function Get-SystemInfo {
    $os   = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cpu  = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    $gpu  = Get-CimInstance -ClassName Win32_VideoController -ErrorAction SilentlyContinue | Where-Object { $_.AdapterRAM -gt 0 } | Select-Object -First 1
    $ram  = [math]::Round((Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue).TotalPhysicalMemory / 1GB)
    $disk = Get-PhysicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.DeviceID -eq '0' } | Select-Object -First 1

    $gpuVendor = 'Unknown'
    if ($gpu) {
        if     ($gpu.Name -match 'NVIDIA|GeForce|RTX|GTX')  { $gpuVendor = 'NVIDIA' }
        elseif ($gpu.Name -match 'AMD|Radeon|RX')           { $gpuVendor = 'AMD' }
        elseif ($gpu.Name -match 'Intel|Arc|UHD|Iris')      { $gpuVendor = 'Intel' }
    }

    $cpuVendor = 'Unknown'
    if ($cpu) {
        if     ($cpu.Name -match 'AMD|Ryzen|Threadripper') { $cpuVendor = 'AMD' }
        elseif ($cpu.Name -match 'Intel|Core|Xeon')        { $cpuVendor = 'Intel' }
    }

    $diskType = 'Unknown'
    if ($disk) {
        if     ($disk.BusType -eq 'NVMe')     { $diskType = 'NVMe SSD' }
        elseif ($disk.MediaType -eq 'SSD')    { $diskType = 'SATA SSD' }
        else                                  { $diskType = 'HDD' }
    }

    return @{
        OSCaption  = if ($os)  { $os.Caption }  else { 'Unknown' }
        OSBuild    = if ($os)  { $os.BuildNumber } else { '0' }
        CPUName    = if ($cpu) { $cpu.Name } else { 'Unknown' }
        CPUVendor  = $cpuVendor
        CPUCores   = if ($cpu) { $cpu.NumberOfCores } else { 0 }
        CPUThreads = if ($cpu) { $cpu.NumberOfLogicalProcessors } else { 0 }
        GPUName    = if ($gpu) { $gpu.Name } else { 'Unknown' }
        GPUVendor  = $gpuVendor
        RAMTotal   = $ram
        DiskType   = $diskType
        IsWin11    = if ($os)  { [int]$os.BuildNumber -ge 22000 } else { $false }
    }
}


# Append only valid block mappings that are not already present.
# A read/write handle prevents another writer from racing the read + append.
function Add-HostsEntries {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Lines)
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $stream = $null; $reader = $null; $writer = $null
        try {
            $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
            $reader = [IO.StreamReader]::new($stream, [Text.UTF8Encoding]::new($false), $true, 1024, $true)
            $existing = $reader.ReadToEnd()
            $encoding = $reader.CurrentEncoding
            $known = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($line in ($existing -split '\r?\n')) {
                $parts = (($line -split '#', 2)[0].Trim() -split '\s+')
                $address = $null
                if ($parts.Count -ge 2 -and [Net.IPAddress]::TryParse($parts[0], [ref]$address)) {
                    foreach ($domain in $parts[1..($parts.Count - 1)]) { [void]$known.Add($domain) }
                }
            }
            $pending = [Collections.Generic.List[string]]::new()
            foreach ($line in $Lines) {
                $parts = (($line -split '#', 2)[0].Trim() -split '\s+')
                if ($parts.Count -lt 2 -or $parts[0] -notin @('0.0.0.0', '127.0.0.1', '::')) { continue }
                foreach ($domain in $parts[1..($parts.Count - 1)]) {
                    if ([Uri]::CheckHostName($domain) -eq [UriHostNameType]::Dns -and $known.Add($domain)) {
                        $pending.Add("$($parts[0]) $domain")
                    }
                }
            }
            if ($pending.Count) {
                [void]$stream.Seek(0, [IO.SeekOrigin]::End)
                $writer = [IO.StreamWriter]::new($stream, $encoding, 1024, $true)
                if ($existing.Length -and -not $existing.EndsWith("`n")) { $writer.WriteLine() }
                foreach ($line in $pending) { $writer.WriteLine($line) }
                $writer.Flush()
            }
            Write-Host "Hosts: $($pending.Count) new block mappings."
            return
        } catch {
            if ($attempt -eq 3) { throw }
            Start-Sleep -Seconds 1
        } finally {
            if ($writer) { $writer.Dispose() }
            if ($reader) { $reader.Dispose() }
            if ($stream) { $stream.Dispose() }
        }
    }
}

function Set-NvidiaContainerProfile {
    [CmdletBinding()]
    param([ValidateSet('Preserve','Driver','Debloat','Aggressive')][string]$Profile = 'Preserve')
    if ($Profile -eq 'Preserve') { return }
    $localType = switch ($Profile) { 'Driver' { 'Automatic' }; 'Aggressive' { 'Manual' }; default { 'Disabled' } }
    Set-ServiceSafe -Name 'NvContainerLocalSystem' -StartupType $localType -StopIfRunning:($localType -eq 'Disabled') | Out-Null
    if ($Profile -ne 'Driver') {
        Set-ServiceSafe -Name 'NvContainerNetworkService' -StartupType Disabled -StopIfRunning | Out-Null
    }
}

function Get-RegistryValueBackup {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    $exists = $false; $value = $null; $type = $null
    if (Test-Path -LiteralPath $Path -ErrorAction Stop) {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        $exists = $key.GetValueNames() -contains $Name
        if ($exists) {
            $value = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $type = [string]$key.GetValueKind($Name)
        }
    }
    [pscustomobject]@{ Path=$Path; Name=$Name; Value=$value; Type=$type; ExistedBefore=$exists }
}

function Clear-WindowsUpdateCache {
    [CmdletBinding()]
    param()
    $services = @(Get-Service -Name wuauserv, BITS -ErrorAction Stop)
    if (@($services | Where-Object { $_.Status -notin @('Running','Stopped') }).Count) {
        throw 'Update services are changing state. Retry once their current operation has finished.'
    }
    $running = @($services | Where-Object Status -eq 'Running' | Select-Object -ExpandProperty Name)
    $restoreFailed = $false
    try {
        foreach ($service in $services) {
            if ($service.Status -ne 'Stopped') {
                # Request stop without killing the process, then bound the wait.
                $service.Stop()
                $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
            }
        }
        # Check again immediately before deleting, since a trigger can restart a service.
        foreach ($service in $services) {
            $service.Refresh()
            if ($service.Status -ne 'Stopped') { throw "$($service.Name) is still running; cache was not deleted." }
        }
        $download = Join-Path $env:windir 'SoftwareDistribution\Download'
        if (Test-Path -LiteralPath $download -ErrorAction Stop) {
            Get-ChildItem -LiteralPath $download -Force -ErrorAction Stop | Remove-Item -Recurse -Force -ErrorAction Stop
        }
    } finally {
        foreach ($name in $running) {
            try { Start-Service -Name $name -ErrorAction Stop }
            catch { $restoreFailed = $true; Write-Warning "Could not restart $name after cleanup: $($_.Exception.Message)" }
        }
    }
    if ($restoreFailed) { throw 'Cache cleanup finished, but a previously running service could not be restarted.' }
    Write-Host 'Windows Update download cache cleaned; previous running services restored.'
}


function Get-ServiceBackup {
    [CmdletBinding()]
    param([string[]]$Names)
    foreach ($service in (Get-CimInstance Win32_Service -ErrorAction Stop)) {
        if ($Names -and $service.Name -notin $Names) { continue }
        $delayed = Get-RegistryValueBackup -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)" -Name DelayedAutoStart
        $type = switch ($service.StartMode) { 'Auto' { 'Automatic' }; 'Demand' { 'Manual' }; default { $service.StartMode } }
        [pscustomobject]@{
            Name=$service.Name; Status=$service.State; StartType=$type
            DelayedAutoStart=$delayed.Value; DelayedAutoStartExisted=$delayed.ExistedBefore
        }
    }
}

function Restore-ServiceBackup {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Entry)
    $savedType = if ($Entry.PSObject.Properties['StartType']) { $Entry.StartType } else { $Entry.StartupType }
    $type = switch ($savedType) { 'Auto' { 'Automatic' }; 'Demand' { 'Manual' }; default { $savedType } }
    if ($type -notin @('Automatic','Manual','Disabled')) { throw "Unsupported startup type: $savedType" }
    Set-Service -Name $Entry.Name -StartupType $type -ErrorAction Stop
    if ($Entry.PSObject.Properties['DelayedAutoStartExisted']) {
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$($Entry.Name)"
        if ([string]$Entry.DelayedAutoStartExisted -eq 'True') {
            Set-ItemProperty -LiteralPath $key -Name DelayedAutoStart -Type DWord -Value ([int]$Entry.DelayedAutoStart) -ErrorAction Stop
        } elseif ([string]$Entry.DelayedAutoStartExisted -eq 'False') {
            Remove-ItemProperty -LiteralPath $key -Name DelayedAutoStart -ErrorAction SilentlyContinue
        } else { throw 'Invalid delayed-start metadata.' }
    }
    $current = Get-Service -Name $Entry.Name -ErrorAction Stop
    if ($Entry.Status -eq 'Running' -and $current.Status -ne 'Running') {
        Start-Service -Name $Entry.Name -ErrorAction Stop
    } elseif ($Entry.Status -eq 'Stopped' -and $current.Status -ne 'Stopped') {
        Stop-Service -Name $Entry.Name -ErrorAction Stop
    }
}

# -- Exports --
Export-ModuleMember -Function @(
    'Add-HostsEntries',
    'Set-NvidiaContainerProfile',
    'Get-RegistryValueBackup',
    'Get-ServiceBackup',
    'Restore-ServiceBackup',
    'Clear-WindowsUpdateCache',
    'Get-OptimizerCounters',
    'Reset-OptimizerCounters',
    'Write-Step',
    'Show-Progress',
    'Set-RegistryValue',
    'Remove-RegistryItem',
    'Remove-RegistryProperty',
    'Get-ScheduledTaskByReference',
    'Set-ScheduledTaskState',
    'Disable-ScheduledTasksByPath',
    'Disable-TasksByRegex',
    'Set-ServiceSafe',
    'Set-ServiceState',
    'Invoke-BcdEdit',
    'Get-SystemInfo'
)
