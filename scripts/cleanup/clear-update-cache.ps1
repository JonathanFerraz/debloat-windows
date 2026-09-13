#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
Import-Module "$PSScriptRoot\..\lib\RyzenOptimizer.psm1" -ErrorAction Stop
Clear-WindowsUpdateCache
