# Script de limpeza de arquivos temporários e navegadores
# Requer execução como administrador

# Verifica se está sendo executado como administrador
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Este script requer privilégios de administrador." -ForegroundColor Red
    Write-Host "Por favor, execute o script como administrador."
    pause
    exit
}

Write-Host "`n-- Iniciando limpeza de arquivos temporários e navegadores --`n" -ForegroundColor Cyan

# Função para limpar diretórios
function Clean-Directory {
    param (
        [string]$path,
        [bool]$recreate = $false
    )

    if (Test-Path $path) {
        try {
            Write-Host "Limpando: $path"
            Remove-Item -Path "$path\*" -Force -Recurse -ErrorAction SilentlyContinue

            if ($recreate) {
                Remove-Item -Path $path -Force -Recurse -ErrorAction SilentlyContinue
                New-Item -ItemType Directory -Path $path -Force | Out-Null
            }
        }
        catch {
            Write-Host "Erro ao limpar $path : $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Diretório não encontrado: $path" -ForegroundColor DarkGray
    }
}

# Limpar diretórios temporários do sistema
Clean-Directory -path "$env:WinDir\Temp" -recreate $true
Clean-Directory -path "$env:WinDir\Prefetch" -recreate $true
Clean-Directory -path $env:TEMP -recreate $true
Clean-Directory -path "$env:AppData\Temp" -recreate $true
Clean-Directory -path "$env:HomePath\AppData\LocalLow\Temp" -recreate $true
Clean-Directory -path "$env:SYSTEMDRIVE\AMD" -recreate $false
Clean-Directory -path "$env:SYSTEMDRIVE\NVIDIA" -recreate $false
Clean-Directory -path "$env:SYSTEMDRIVE\INTEL" -recreate $false

# Limpar lixeira
Write-Host "`n-- Esvaziando Lixeira --" -ForegroundColor Cyan
Clear-RecycleBin -Force -ErrorAction SilentlyContinue
Write-Host "Lixeira limpa com sucesso." -ForegroundColor Green

# Limpar navegadores
Write-Host "`n-- Limpando histórico de navegadores --" -ForegroundColor Cyan

# Chrome
Clean-Directory -path "$env:LocalAppData\Google\Chrome\User Data\Default\Cache"
Remove-Item -Path "$env:LocalAppData\Google\Chrome\User Data\Default\History" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:LocalAppData\Google\Chrome\User Data\Default\Cookies" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:LocalAppData\Google\Chrome\User Data\Default\Media Cache" -Force -Recurse -ErrorAction SilentlyContinue

# Edge
Clean-Directory -path "$env:LocalAppData\Microsoft\Edge\User Data\Default\Cache"
Remove-Item -Path "$env:LocalAppData\Microsoft\Edge\User Data\Default\History" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:LocalAppData\Microsoft\Edge\User Data\Default\Cookies" -Force -ErrorAction SilentlyContinue

# Firefox
Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles\" -Filter "*.default*" | ForEach-Object {
    $profilePath = $_.FullName
    Clean-Directory -path "$profilePath\cache2\entries"
    Remove-Item -Path "$profilePath\places.sqlite" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$profilePath\cookies.sqlite" -Force -ErrorAction SilentlyContinue
}

# Limpar logs do sistema (adicionado)
Write-Host "`n-- Limpando logs do sistema --" -ForegroundColor Cyan
Clean-Directory -path "$env:WinDir\Logs"
wevtutil el | ForEach-Object { wevtutil cl $_ }

# Limpar memória (adicionado)
Write-Host "`n-- Otimizando memória --" -ForegroundColor Cyan
Write-Host "Liberando memória antes: $((Get-Counter '\Memory\Available MBytes').CounterSamples.CookedValue) MB disponíveis"
(42).ToString() | Out-Null # Operação dummy para limpar pipeline
[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()
Write-Host "Liberando memória depois: $((Get-Counter '\Memory\Available MBytes').CounterSamples.CookedValue) MB disponíveis"

# Verificação de espaço liberado (adicionado)
$freedSpace = (Get-PSDrive -Name $env:SystemDrive[0]).Free / 1GB
Write-Host "`n-- Espaço livre em $env:SystemDrive : $($freedSpace.ToString('N2')) GB --" -ForegroundColor Green

Write-Host "`nLimpeza concluída com sucesso!`n" -ForegroundColor Green
pause