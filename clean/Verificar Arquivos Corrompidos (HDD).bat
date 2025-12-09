@echo off
echo Otimizando sistema...
defrag C: /O
sfc /scannow
DISM /Online /Cleanup-Image /RestoreHealth
echo Otimização completa!
pause
