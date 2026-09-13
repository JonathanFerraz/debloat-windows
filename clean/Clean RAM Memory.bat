@echo off
Title OTIMIZANDO MEMORIA RAM...

set "emptyStandbyList=%~dp0EmptyStandbyList.exe"

if not exist "%emptyStandbyList%" (
    echo [ERRO] O arquivo EmptyStandbyList.exe nao foi encontrado.
    echo Certifique-se de que ele esta na mesma pasta deste script.
    pause
    exit /b 1
)

echo Limpando o cache de memoria RAM...
"%emptyStandbyList%" workingsets
if errorlevel 1 goto failed
"%emptyStandbyList%" modifiedpagelist
if errorlevel 1 goto failed
"%emptyStandbyList%" standbylist
if errorlevel 1 goto failed
echo Working sets e listas de memoria limpos.


pause
exit /b 0

:failed
echo [ERRO] EmptyStandbyList falhou. Execute como administrador e verifique o programa.
pause
exit /b 1
