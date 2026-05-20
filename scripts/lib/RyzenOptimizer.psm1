<#
.SYNOPSIS
    R Y Z E N Optimizer - Shared Module v3.0
.DESCRIPTION
    Unified helper functions for all Ryzen Optimizer scripts.
    Import with: Import-Module "$PSScriptRoot\..\lib\RyzenOptimizer.psm1" -Force
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
            New-Item -Path $Path -Force | Out-Null
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
        Write-Verbose "Failed to set registry value: $Path\$Name - $($_.Exception.Message)"
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
function Set-ScheduledTaskState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TaskName,
        [Parameter(Mandatory)][ValidateSet('Enable','Disable')][string]$Action
    )
    try {
        if ($Action -eq 'Enable') {
            Enable-ScheduledTask -TaskName $TaskName -ErrorAction Stop | Out-Null
        } else {
            Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            Disable-ScheduledTask -TaskName $TaskName -ErrorAction Stop | Out-Null
        }
        $script:Counters.TaskSuccess++
        return $true
    }
    catch {
        $script:Counters.TaskFail++
        return $false
    }
}

function Disable-ScheduledTasksByPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$TaskPaths)
    foreach ($tp in $TaskPaths) {
        $task = Get-ScheduledTask -TaskPath $tp -ErrorAction SilentlyContinue
        if ($task -and $task.State -ne 'Disabled') {
            try { $task | Disable-ScheduledTask -ErrorAction Stop | Out-Null; $script:Counters.TaskSuccess++ }
            catch { $script:Counters.TaskFail++ }
        }
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
                    if ($_.State -ne 'Disabled') { $_ | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null }
                    $script:Counters.TaskSuccess++
                } catch { $script:Counters.TaskFail++ }
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
            Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
        }
        Set-Service -Name $Name -StartupType $StartupType -ErrorAction Stop
        $script:Counters.ServiceSuccess++
        return $true
    }
    catch {
        $script:Counters.ServiceFail++
        return $false
    }
}

function Set-ServiceState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$ServiceNames,
        [Parameter(Mandatory)][ValidateSet('Disabled','Automatic','Manual')][string]$StartupType,
        [string]$Status = 'Stopped'
    )
    foreach ($service in $ServiceNames) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc) {
            try {
                Set-Service -Name $service -StartupType $StartupType -ErrorAction Stop
                if ($svc.Status -eq 'Running') { Stop-Service -Name $service -Force -ErrorAction SilentlyContinue }
                $script:Counters.ServiceSuccess++
            } catch { $script:Counters.ServiceFail++ }
        }
    }
}

# -- BCDEdit --
function Invoke-BcdEdit {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Arguments)
    try {
        Invoke-Expression "bcdedit.exe $Arguments" 2>&1 | Out-Null
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

# -- Exports --
Export-ModuleMember -Function @(
    'Get-OptimizerCounters',
    'Reset-OptimizerCounters',
    'Write-Step',
    'Show-Progress',
    'Set-RegistryValue',
    'Remove-RegistryItem',
    'Remove-RegistryProperty',
    'Set-ScheduledTaskState',
    'Disable-ScheduledTasksByPath',
    'Disable-TasksByRegex',
    'Set-ServiceSafe',
    'Set-ServiceState',
    'Invoke-BcdEdit',
    'Get-SystemInfo'
)
