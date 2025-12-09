<#
check-services.ps1

Lê as listas $ServicesToStopAndDisable e $ServicesToSetManual do arquivo
`services.ps1` (não executa o arquivo), extrai os nomes das entradas e verifica
cada serviço usando Win32_Service (Get-CimInstance).

Uso:
  .\check-services.ps1
  .\check-services.ps1 -ServicesFile "..\services.ps1"
  .\check-services.ps1 -OutCsv C:\temp\services-report.csv

O script tenta localizar serviços por ServiceName e por DisplayName.
#>

param(
    [string]$ServicesFile = "$PSScriptRoot\services.ps1",
    [string]$OutCsv
)

function Get-ArrayFromFile {
    param(
        [string]$Content,
        [string]$VariableName
    )

    # Pattern: $VariableName = @( ... )  (singleline to capture across lines)
    $pattern = '\$' + [regex]::Escape($VariableName) + '\s*=\s*@\((.*?)\)'
    $m = [regex]::Match($Content, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $m.Success) { return @() }

    $inside = $m.Groups[1].Value

    # Match quoted strings (double or single) and ignore lines starting with #
    $names = @()
    $lines = $inside -split "\r?\n"
    foreach ($line in $lines) {
        $trim = $line.Trim()
        if ($trim -like '#*') { continue }
        # capture "..." or '...'
        $dq = [regex]::Matches($trim, '"([^\"]+)"') | ForEach-Object { $_.Groups[1].Value }
        $sq = [regex]::Matches($trim, "'([^']+)'") | ForEach-Object { $_.Groups[1].Value }
        $names += $dq
        $names += $sq
    }

    return $names | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
}

if (-not (Test-Path -Path $ServicesFile)) {
    Write-Error "Arquivo de serviços não encontrado: $ServicesFile"
    exit 2
}

$content = Get-Content -Raw -Path $ServicesFile

$list1 = Get-ArrayFromFile -Content $content -VariableName 'ServicesToStopAndDisable'
$list2 = Get-ArrayFromFile -Content $content -VariableName 'ServicesToSetManual'

$all = ($list1 + $list2) | Select-Object -Unique

if (-not $all -or $all.Count -eq 0) {
    Write-Warning "Nenhum serviço extraído do arquivo. Certifique-se de que as variáveis existam no arquivo e estejam no formato esperado."
    exit 0
}

$results = foreach ($svc in $all) {
    # First try by service name (Name)
    $w = Get-CimInstance -ClassName Win32_Service -Filter "Name = '$svc'" -ErrorAction SilentlyContinue

    if (-not $w) {
        # Try by DisplayName (case-insensitive)
        $w = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -ieq $svc }
    }

    if (-not $w) {
        [PSCustomObject]@{
            InputName   = $svc
            ServiceName = $null
            DisplayName = $null
            State       = 'NotFound'
            StartMode   = $null
            StartName   = $null
            PathName    = $null
        }
    }
    else {
        [PSCustomObject]@{
            InputName   = $svc
            ServiceName = $w.Name
            DisplayName = $w.DisplayName
            State       = $w.State
            StartMode   = $w.StartMode
            StartName   = $w.StartName
            PathName    = $w.PathName
        }
    }
}

# Show table on screen
$results | Sort-Object @{Expression='StartMode';Descending=$false}, @{Expression='State';Descending=$true} | Format-Table -AutoSize

# Emit results object to pipeline for further processing
$results

if ($PSBoundParameters.ContainsKey('OutCsv')) {
    try {
        $results | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
        Write-Host "Relatório salvo em: $OutCsv"
    }
    catch {
        Write-Warning "Não foi possível salvar CSV: $($_.Exception.Message)"
    }
}

# Quick helpers (display examples for the user)
Write-Host "`nExemplos:`n" -ForegroundColor Cyan
Write-Host "  # Mostrar apenas serviços habilitados (StartMode diferente de 'Disabled')"
Write-Host "  `\$results | Where-Object { `\$_.StartMode -ne 'Disabled' } | Format-Table -AutoSize"
Write-Host "  # Mostrar apenas serviços stopped"
Write-Host "  `\$results | Where-Object { `\$_.State -ne 'Running' } | Format-Table -AutoSize"
