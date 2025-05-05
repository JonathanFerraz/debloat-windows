@echo off
:: ==============================================
:: Windows Debloat & Optimization Script
:: Versão: 3.0 | Data: 2025-04-27
:: ==============================================
:: Descrição:
:: Este script realiza desbloat completo, otimizações
:: de sistema e configurações de privacidade no Windows
:: ==============================================

:: ----------------------------
:: Verificação de Administrador
:: ----------------------------
NET FILE > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERRO] Este script requer privilégios de administrador
    echo Execute como Administrador e tente novamente
    echo.
    pause
    exit /b
)

:: ----------------------------
:: Configurações Iniciais
:: ----------------------------
setlocal EnableDelayedExpansion
color 0a
title Windows Debloat Tool v3.0
echo.
echo ==============================================
echo INICIANDO PROCESSO DE OTIMIZAÇÃO
echo ==============================================

:: ---------------------------------
:: 1. Criação de Ponto de Restauração
:: ---------------------------------
echo.
echo [ETAPA 1/8] Criando ponto de restauração...
powershell -command "Enable-ComputerRestore -Drive $env:SystemDrive"
powershell -command "Checkpoint-Computer -Description 'Pre-Debloat' -RestorePointType 'MODIFY_SETTINGS'"
if %ERRORLEVEL% EQU 0 (
    echo [SUCESSO] Ponto de restauração criado
) else (
    echo [AVISO] Falha ao criar ponto de restauração
)

:: ----------------------------
:: 2. Limpeza de Sistema
:: ----------------------------
echo.
echo [ETAPA 2/8] Executando limpeza de sistema...
call "%~dp0assets\remove-temp.bat"
echo.
echo Executando limpeza de disco...
cleanmgr /verylowdisk /sagerun:5
echo.
echo Verificando integridade do sistema...
sfc /scannow

:: ----------------------------
:: 3. Remoção de Aplicativos
:: ----------------------------
echo.
echo [ETAPA 3/8] Removendo aplicativos desnecessários...
call "%~dp0assets\remove-apps.bat"
call "%~dp0assets\remove-edge.bat"
call "%~dp0assets\ms-gamebar-annoyance.bat"

:: ----------------------------
:: 4. Otimizações de Rede
:: ----------------------------
echo.
echo [ETAPA 4/8] Otimizando configurações de rede...
echo Redefinindo configurações TCP/IP...
ipconfig /flushdns
ipconfig /release
ipconfig /renew
netsh interface ip set dns name="Ethernet" static 8.8.8.8
netsh interface ip add dns name="Ethernet" 8.8.4.4 index=2
netsh int tcp set global rss=disabled
netsh int tcp set global autotuninglevel=restricted

:: ----------------------------
:: 5. Desativação de Recursos
:: ----------------------------
echo.
echo [ETAPA 5/8] Desativando recursos do Windows...
echo Desativando Internet Explorer...
dism /online /Remove-Capability /CapabilityName:Browser.InternetExplorer~~~~0.0.11.0 /NoRestart

echo Desativando Hyper-V...
dism /online /Disable-Feature /FeatureName:Microsoft-Hyper-V-All /NoRestart

echo Desativando Windows Media Player...
dism /online /Disable-Feature /FeatureName:WindowsMediaPlayer /NoRestart

echo Desativando Recall...
DISM /Online /Disable-Feature /FeatureName:Recall /NoRestart

:: ----------------------------
:: 6. Configurações do Sistema
:: ----------------------------
echo.
echo [ETAPA 6/8] Aplicando otimizações de sistema...
call "%~dp0assets\V2\registry_v2.bat"
call "%~dp0services.bat"
call "%~dp0assets\telemetry.bat"

:: ----------------------------
:: 7. Configurações de Energia
:: ----------------------------
echo.
echo [ETAPA 7/8] Configurando plano de energia...
echo Ativando modo Ultimate Performance...
powershell -command "$scheme = powercfg -list | Select-String 'Ultimate Performance'; if (-not $scheme) { powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 }"
for /f "tokens=2 delims=:(" %%i in ('powercfg -list ^| findstr "Ultimate Performance"') do (
    powercfg -setactive %%i
)
echo Desativando hibernação...
powercfg /hibernate off

:: ----------------------------
:: 8. Finalização
:: ----------------------------
echo.
echo [ETAPA 8/8] Finalizando otimizações...
call "%~dp0assets\finish-optimization.bat"

:: ----------------------------
:: Conclusão
:: ----------------------------
echo.
echo ==============================================
echo OTIMIZAÇÃO CONCLUÍDA COM SUCESSO!
echo ==============================================
echo.
echo Recomendações:
echo 1. Reinicie seu computador
echo 2. Verifique se todos os drivers estão atualizados
echo 3. Configure seus programas essenciais
echo.
echo Observações:
echo - Algumas alterações requerem reinicialização
echo - Recursos removidos não estarão disponíveis
echo.
pause

:: Reiniciar Explorer para aplicar mudanças
taskkill /f /im explorer.exe >nul
start explorer.exe
exit /b 0