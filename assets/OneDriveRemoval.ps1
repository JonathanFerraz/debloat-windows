
    try {
        # Stop OneDrive processes
        $processesToStop = @("OneDrive", "FileCoAuth", "FileSyncHelper")
        foreach ($processName in $processesToStop) { 
            Get-Process -Name $processName -ErrorAction SilentlyContinue | 
            Stop-Process -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 1
    }
    catch {
        # Continue if process stopping fails
    }
    
    # Check and execute uninstall strings from registry
    $registryPaths = @(
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OneDriveSetup.exe",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OneDriveSetup.exe"
    )

    foreach ($regPath in $registryPaths) {
        try {
            if (Test-Path $regPath) {
                $uninstallString = (Get-ItemProperty -Path $regPath -ErrorAction Stop).UninstallString
                if ($uninstallString) {
                    if ($uninstallString -match '^"([^"]+)"(.*)$') {
                        $exePath = $matches[1]
                        $args = $matches[2].Trim()
                        Start-Process -FilePath $exePath -ArgumentList $args -NoNewWindow -Wait -ErrorAction SilentlyContinue
                    }
                    else {
                        Start-Process -FilePath $uninstallString -NoNewWindow -Wait -ErrorAction SilentlyContinue
                    }
                }
            }
        }
        catch {
            # Continue if registry operation fails
            continue
        }
    }

    try {
        # Remove OneDrive AppX package
        Get-AppxPackage -Name "*OneDrive*" -ErrorAction SilentlyContinue | 
        Remove-AppxPackage -ErrorAction SilentlyContinue
    }
    catch {
        # Continue if AppX removal fails
    }
    
    # Uninstall OneDrive using setup files
    $oneDrivePaths = @(
        "$env:SystemRoot\SysWOW64\OneDriveSetup.exe",
        "$env:SystemRoot\System32\OneDriveSetup.exe",
        "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe"
    )
    
    foreach ($path in $oneDrivePaths) {
        try {
            if (Test-Path $path) {
                Start-Process -FilePath $path -ArgumentList "/uninstall" -NoNewWindow -Wait -ErrorAction SilentlyContinue
            }
        }
        catch {
            # Continue if uninstall fails
            continue
        }
    }
    
    try {
        # Remove OneDrive scheduled tasks
        Get-ScheduledTask -ErrorAction SilentlyContinue | 
        Where-Object { $_.TaskName -match 'OneDrive' -and $_.TaskName -ne 'OneDriveRemoval' } | 
        ForEach-Object { 
            Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction SilentlyContinue 
        }
    }
    catch {
        # Continue if task removal fails
    }
    
    try {
        # Configure registry settings
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force -ErrorAction SilentlyContinue | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name "KFMBlockOptIn" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        
        # Remove OneDrive from startup
        Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveSetup" -ErrorAction SilentlyContinue
        
        # Remove OneDrive from Navigation Pane
        Remove-Item -Path "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -Force -ErrorAction SilentlyContinue
    }
    catch {
        # Continue if registry operations fail
    }
    
    # Function to handle robust folder removal
    function Remove-OneDriveFolder {
        param ([string]$folderPath)
        
        if (-not (Test-Path $folderPath)) {
            return
        }
        
        try {
            # Stop OneDrive processes if they're running
            Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue | 
            Stop-Process -Force -ErrorAction SilentlyContinue
            
            # Take ownership and grant permissions
            $null = Start-Process "takeown.exe" -ArgumentList "/F `"$folderPath`" /R /A /D Y" -Wait -NoNewWindow -PassThru -ErrorAction SilentlyContinue
            $null = Start-Process "icacls.exe" -ArgumentList "`"$folderPath`" /grant administrators:F /T" -Wait -NoNewWindow -PassThru -ErrorAction SilentlyContinue
            
            # Try direct removal
            Remove-Item -Path $folderPath -Force -Recurse -ErrorAction SilentlyContinue
        }
        catch {
            try {
                # If direct removal fails, create and execute a cleanup batch file
                $batchPath = "$env:TEMP\RemoveOneDrive_$(Get-Random).bat"
                $batchContent = @"
@echo off
timeout /t 2 /nobreak > nul
takeown /F "$folderPath" /R /A /D Y
icacls "$folderPath" /grant administrators:F /T
rd /s /q "$folderPath"
del /F /Q "%~f0"
"@
                Set-Content -Path $batchPath -Value $batchContent -Force -ErrorAction SilentlyContinue
                Start-Process "cmd.exe" -ArgumentList "/c $batchPath" -WindowStyle Hidden -ErrorAction SilentlyContinue
            }
            catch {
                # Continue if batch file cleanup fails
            }
        }
    }

    # Files to remove (single items)
    $filesToRemove = @(
        "$env:ALLUSERSPROFILE\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk",
        "$env:ALLUSERSPROFILE\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.exe",
        "$env:PUBLIC\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk",
        "$env:PUBLIC\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.exe",
        "$env:SystemRoot\System32\OneDriveSetup.exe",
        "$env:SystemRoot\SysWOW64\OneDriveSetup.exe",
        "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"
    )

    # Remove single files
    foreach ($file in $filesToRemove) {
        try {
            if (Test-Path $file) {
                Remove-Item $file -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            # Continue if file removal fails
            continue
        }
    }

    # Folders that need special handling
    $foldersToRemove = @(
        "$env:ProgramFiles\Microsoft\OneDrive",
        "$env:ProgramFiles\Microsoft OneDrive",
        "$env:LOCALAPPDATA\Microsoft\OneDrive"
    )

    # Remove folders with robust method
    foreach ($folder in $foldersToRemove) {
        try {
            Remove-OneDriveFolder -folderPath $folder
        }
        catch {
            # Continue if folder removal fails
            continue
        }
    }

    # Additional cleanup for stubborn setup files
    $setupFiles = @(
        "$env:SystemRoot\System32\OneDriveSetup.exe",
        "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
    )

    foreach ($file in $setupFiles) {
        if (Test-Path $file) {
            try {
                # Take ownership and grant full permissions
                $null = Start-Process "takeown.exe" -ArgumentList "/F `"$file`"" -Wait -NoNewWindow -PassThru -ErrorAction SilentlyContinue
                $null = Start-Process "icacls.exe" -ArgumentList "`"$file`" /grant administrators:F" -Wait -NoNewWindow -PassThru -ErrorAction SilentlyContinue
            
                # Attempt direct removal
                Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
            
                # If file still exists, schedule it for deletion on next reboot
                if (Test-Path $file) {
                    $pendingRename = "$file.pending"
                    Move-Item -Path $file -Destination $pendingRename -Force -ErrorAction SilentlyContinue
                    Start-Process "cmd.exe" -ArgumentList "/c del /F /Q `"$pendingRename`"" -WindowStyle Hidden -ErrorAction SilentlyContinue
                }
            }
            catch {
                # Continue if cleanup fails
                continue
            }
        }
    }

