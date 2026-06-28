# Cleanup Bloat from AMD Radeon Drivers
# https://github.com/GSDragoon/RadeonSoftwarePostInstallDebloat

param(
    [switch]$EnableTrace,
    [switch]$AutoReboot
)

# Need to run as Admin, self-elevate the script, if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
    Start-Process -FilePath "powershell.exe" -Verb Runas -ArgumentList $CommandLine
    Exit
}

# Echos commands as they run (optional)
if ($EnableTrace) {
    Set-PSDebug -Trace 1
}


# End the existing Radeon Software and other Radeon Settings processes
Write-Host "Exiting Radeon Software"
$cncmdPath = "C:\Program Files\AMD\CNext\CNext\cncmd.exe"
if (Test-Path $cncmdPath) {
    Start-Process -FilePath $cncmdPath -ArgumentList 'exit' -Wait
}
else {
    Write-Host "cncmd.exe not found. Skipping Radeon Software exit command."
}

# NT Services - Stop and disable them
Write-Host "Stopping and Disabling NT Services"
# AMD User Experience Program Launcher (https://www.amd.com/en/corporate/amd-user-experience)
if (Get-Service -Name "AUEPLauncher" -ErrorAction SilentlyContinue) {
    try {
        Stop-Service -Name "AUEPLauncher" -ErrorAction Stop
        Set-Service -Name "AUEPLauncher" -StartupType Disabled -ErrorAction Stop
    } catch {
        Write-Warning "Could not stop/disable AUEPLauncher: $($_.Exception.Message)"
    }
}
# AMD External Events Utility (probably want this one)
if (Get-Service -Name "AMD External Events Utility" -ErrorAction SilentlyContinue) {
    # Probably want this service running
    #Stop-Service -Name "AMD External Events Utility"
    #Set-Service -Name "AMD External Events Utility" -StartupType Disabled
}

# Scheduled Tasks - End and disable them
Write-Host "Ending and Disabling Scheduled Tasks"
$schtasksPath = Join-Path $env:SystemRoot 'System32\schtasks.exe'

function Invoke-Schtask {
    param([string[]]$Arguments)
    if (Test-Path $schtasksPath) {
        & $schtasksPath @Arguments
    }
}

# AMDInstallLauncher - Installs AMD User Experience Program (https://www.amd.com/en/corporate/amd-user-experience)
#Start-Process -FilePath "$env:systemroot\system32\schtasks.exe" -ArgumentList '/End /TN "AMDInstallLauncher"' -Wait
#Start-Process -FilePath "$env:systemroot\system32\schtasks.exe" -ArgumentList '/Change /TN "AMDInstallLauncher" /DISABLE' -Wait
Invoke-Schtask -Arguments @('/End', '/TN', 'AMDInstallLauncher')
Invoke-Schtask -Arguments @('/Change', '/TN', 'AMDInstallLauncher', '/DISABLE')
# AMDLinkUpdate - AMD Link Update
Invoke-Schtask -Arguments @('/End', '/TN', 'AMDLinkUpdate')
Invoke-Schtask -Arguments @('/Change', '/TN', 'AMDLinkUpdate', '/DISABLE')
# ModifyLinkUpdate - AMD Link Update Current User
Invoke-Schtask -Arguments @('/End', '/TN', 'ModifyLinkUpdate')
Invoke-Schtask -Arguments @('/Change', '/TN', 'ModifyLinkUpdate', '/DISABLE')
# StartCN - Starts the main RadeonSoftware process, probably want this one
#.\schtasks.exe /End /TN "StartCN"
#.\schtasks.exe /Change /TN "StartCN" /DISABLE
# StartDVR - Radeon Settings Host Service and Radeon Settings Desktop Overlay. For virtual reality devices?
Invoke-Schtask -Arguments @('/End', '/TN', 'StartDVR')
Invoke-Schtask -Arguments @('/Change', '/TN', 'StartDVR', '/DISABLE')

# Uninstall AMD WVR64 (Virtual reality stuff)
Write-Host "Uninstalling AMD WVR64"
# TODO: Look this up in the registry in case the GUID changes?
Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList '/uninstall "{284967ee-7da2-4fc6-b14a-361266a50448}" /quiet' -Wait
# msiexec.exe /uninstall "{284967ee-7da2-4fc6-b14a-361266a50448}" /quiet

# Rename RSServCmd.exe so it doesn't run when RadeonSoftware.exe runs
# RSServCmd starts the Radeon Settings: Host Service (AMDRSServ.exe) and Radeon Settings: Desktop Overlay (amdow.exe) processes, and probably more depending on the system
Write-Host "Renaming RSServCmd to prevent RadeonSoftware from running additional processes"
if (Test-Path -Path "C:\Program Files\AMD\CNext\CNext\RSServCmd.exe") {
    # Support being able to run this multiple times without issues
    # If both the original file and the renamed one exist (such as from a new driver install), then delte the old renamed file first (the rename will fail if it already exists)
    if (Test-Path -Path "C:\Program Files\AMD\CNext\CNext\RSServCmd.exe.ChangedToNotRun") {	
        Remove-Item -Path "C:\Program Files\AMD\CNext\CNext\RSServCmd.exe.ChangedToNotRun"
    }
	
    Rename-Item -Path "C:\Program Files\AMD\CNext\CNext\RSServCmd.exe" -NewName "RSServCmd.exe.ChangedToNotRun"
}

# Prompt to restart computer when done
if ($EnableTrace) {
    Set-PSDebug -Trace 0
}

if ($AutoReboot) {
    Write-Host "Complete. Rebooting now..."
    Restart-Computer
}
else {
    Write-Host "Complete. Reboot is recommended."
    $shouldReboot = Read-Host "Reboot now? (S/N)"
    if ($shouldReboot -match '^(S|s|Y|y)$') {
        Restart-Computer
    }
}
# Restart-Computer -Confirm