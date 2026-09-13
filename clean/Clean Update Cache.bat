@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\scripts\cleanup\clear-update-cache.ps1"
if errorlevel 1 (
    echo [ERRO] A limpeza falhou. Verifique as mensagens acima.
    pause
    exit /b 1
)
echo Cache do Windows Update limpo!
pause
