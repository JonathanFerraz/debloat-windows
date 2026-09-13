@echo off
title Limpeza Completa do PC
set "cleanupMode=%~1"
if not defined cleanupMode set "cleanupMode=Full"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\scripts\cleanup\remove-temp.ps1" -Mode "%cleanupMode%"
if errorlevel 1 (
    echo [ERRO] A limpeza falhou. Verifique as mensagens acima.
    pause
    exit /b 1
)
echo Limpeza concluida.
pause
