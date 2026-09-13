#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$RegistryBackup,
    [switch]$ResetGraphicsDefaults,
    [switch]$ResetBootTimingOverrides
)

$ErrorActionPreference = 'Stop'
if (-not $RegistryBackup -and -not $ResetGraphicsDefaults) {
    throw 'Pass -RegistryBackup with a pre-debloat registry backup folder, or explicitly use -ResetGraphicsDefaults. See docs/ANALISE.md.'
}
if ($RegistryBackup -and $ResetGraphicsDefaults) { throw 'Choose a backup restore OR graphics defaults.' }

if ($RegistryBackup) {
    $xml = Join-Path $RegistryBackup 'registry-values-backup.xml'
    $csv = Join-Path $RegistryBackup 'registry-values-backup.csv'
    $entries = if (Test-Path -LiteralPath $xml) { @(Import-Clixml -LiteralPath $xml) } else { @(Import-Csv -LiteralPath $csv) }
    # Restore performance/compatibility values only. Preserve privacy and UI debloat.
    $prefixes = @(
        'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers',
        'HKLM:\SOFTWARE\Microsoft\Windows\Dwm',
        'HKLM:\SOFTWARE\Microsoft\DirectX', 'HKLM:\SOFTWARE\Microsoft\Direct3D',
        'HKCU:\Software\Microsoft\DirectX', 'HKCU:\Software\Microsoft\Avalon.Graphics',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power',
        'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Power',
        'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem',
        'HKLM:\SOFTWARE\Microsoft\Dfrg',
        'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters',
        'HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters',
        'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched',
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile',
        'HKLM:\SYSTEM\CurrentControlSet\Services\amdkmdag',
        'HKLM:\SYSTEM\CurrentControlSet\Services\USB',
        'HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters',
        'HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters',
        'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time',
        'HKLM:\SYSTEM\CurrentControlSet\Services\SysMain',
        'HKLM:\SYSTEM\ControlSet001\Services\Ndu',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard',
        'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\HypervisorEnforcedCodeIntegrity',
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    )
    $specificNames = @('GPU_SCHEDULER_MODE', 'SvcHostSplitThresholdInKB', 'WaitToKillServiceTimeout',
        'AutoEndTasks', 'HungAppTimeout', 'WaitToKillAppTimeout', 'ForegroundLockTimeout',
        'AutoGameModeEnabled', 'AllowAutoGameMode', 'MaintenanceDisabled', 'SearchOrderConfig',
        'GameDVR_FSEBehavior', 'GameDVR_FSEBehaviorMode', 'GameDVR_DXGIHonorFSEWindowsCompatible', 'GameDVR_HonorUserFSEBehaviorMode')
    $entries = @($entries | Where-Object {
        $entry = $_
        $matched = @($prefixes | Where-Object { $entry.Path -ieq $_ -or $entry.Path.StartsWith($_ + '\', [StringComparison]::OrdinalIgnoreCase) }).Count
        $matched -gt 0 -or $entry.Name -in $specificNames
    })
} else {
    # Explicit fallback when the original backup is unavailable. Delete only
    # named overrides from this project's old graphics profile, never whole keys.
    $graphics = @{
        'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' = @('HwSchMode', 'TdrDelay', 'TdrDdiDelay', 'DisableMultiplaneOverlay', 'FrameQueueLimit', 'DxgKrnlLatencyPolicy', 'VulkanPreQueueCount', 'GpuComputeStallPolicy', 'FrameLatency', 'Attributes')
        'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler' = @('EnablePreemptiveSubmit', 'AsyncQueueDelay')
        'HKLM:\SOFTWARE\Microsoft\Windows\Dwm' = @('OverlayTestMode', 'FlipQueueSize')
        'HKCU:\System\GameConfigStore' = @('GameDVR_FSEBehavior', 'GameDVR_FSEBehaviorMode', 'GameDVR_DXGIHonorFSEWindowsCompatible', 'GameDVR_HonorUserFSEBehaviorMode')
        'HKCU:\Software\Microsoft\Avalon.Graphics' = @('MaxMultisampleType', 'DisableHWAcceleration')
        'HKLM:\SOFTWARE\Microsoft\DirectX' = @('MaxFrameLatency', 'DisableThreadedOptimizations')
        'HKLM:\SOFTWARE\Microsoft\Direct3D\Global' = @('MaxQueuedFrames', 'EnableMultiThreadedRendering', 'DisableVSync')
        'HKLM:\SYSTEM\CurrentControlSet\Services\amdkmdag' = @('PP_DisablePowerGating')
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' = @('GPU_SCHEDULER_MODE')
    }
    $entries = @(foreach ($path in $graphics.Keys) {
        foreach ($name in $graphics[$path]) { [pscustomobject]@{ Path = $path; Name = $name; ExistedBefore = $false; Value = $null; Type = 'DWord' } }
    })
    Write-Warning 'Graphics defaults are a partial reset, not a reconstruction of your original settings.'
}
if (-not $entries.Count) { throw 'No matching recovery entries found.' }
foreach ($entry in $entries) {
    if ($entry.Path -notmatch '^HK(LM|CU):\\' -or [string]::IsNullOrWhiteSpace($entry.Name)) { throw 'Invalid backup registry path/name.' }
    if ([string]$entry.ExistedBefore -notin @('True', 'False')) { throw 'Invalid ExistedBefore in backup.' }
    if ([string]$entry.ExistedBefore -eq 'True' -and [string]$entry.Type -notin @('DWord', 'QWord', 'String', 'ExpandString', 'MultiString', 'Binary')) { throw 'Unsupported backup registry type.' }
}
if (-not $PSCmdlet.ShouldProcess('Legacy performance overrides', 'Back up current values and apply selected recovery')) { return }

$backupDir = Join-Path "$env:SystemDrive\Ryzen Optimizer\Backup" ('registry-repair-' + (Get-Date -Format 'yyyy-MM-dd_HH-mm-ss-fff'))
New-Item -ItemType Directory -Path $backupDir -ErrorAction Stop | Out-Null
$before = @(foreach ($entry in $entries) {
    $key = Get-Item -LiteralPath $entry.Path -ErrorAction SilentlyContinue
    $exists = $key -and $key.GetValueNames() -contains $entry.Name
    [pscustomobject]@{
        Path = $entry.Path; Name = $entry.Name; ExistedBefore = [bool]$exists
        Type = if ($exists) { [string]$key.GetValueKind($entry.Name) } else { '' }
        Value = if ($exists) { $key.GetValue($entry.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } else { $null }
    }
})
$before | Export-Clixml -LiteralPath (Join-Path $backupDir 'registry-values-backup.xml') -ErrorAction Stop
$before | Export-Csv -LiteralPath (Join-Path $backupDir 'registry-values-backup.csv') -NoTypeInformation -ErrorAction Stop
foreach ($entry in $entries) {
    if ([string]$entry.ExistedBefore -eq 'True') {
        if (-not (Test-Path -LiteralPath $entry.Path)) { New-Item -Path $entry.Path -Force -ErrorAction Stop | Out-Null }
        New-ItemProperty -LiteralPath $entry.Path -Name $entry.Name -Value $entry.Value -PropertyType ([string]$entry.Type) -Force -ErrorAction Stop | Out-Null
    } elseif (Get-ItemProperty -LiteralPath $entry.Path -Name $entry.Name -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -LiteralPath $entry.Path -Name $entry.Name -ErrorAction Stop
    }
}
if ($ResetBootTimingOverrides) {
    & bcdedit.exe /export (Join-Path $backupDir 'bcd-before.bin')
    if ($LASTEXITCODE -ne 0) { throw 'BCD backup failed; boot settings were not changed.' }
    foreach ($name in @('tscsyncpolicy', 'useplatformclock', 'useplatformtick', 'disabledynamictick')) {
        & bcdedit.exe /deletevalue '{current}' $name
        if ($LASTEXITCODE -ne 0) { Write-Warning "Could not remove BCD $name (it may already be absent)." }
    }
}
Write-Host "Recovery applied. Previous values: $backupDir"
Write-Host 'Restart Windows, then test. Restore devices/services separately from their pre-debloat backups if needed.'
