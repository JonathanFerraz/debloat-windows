@echo off

echo Verificando arquivos de sistema...
sfc /scannow


echo Restaurando a imagem do sistema...
Dism /Online /Cleanup-Image /RestoreHealth


pause
