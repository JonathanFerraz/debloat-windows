@echo off
net stop wuauserv
net stop bits
del /f /s /q %windir%\SoftwareDistribution\Download\*.*
net start wuauserv
net start bits
echo Cache do Windows Update limpo!
pause
