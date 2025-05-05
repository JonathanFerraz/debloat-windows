:: Verifica integridade do sistema
sfc /scannow

:: Otimiza armazenamento
defrag C: /O /U

:: Reinicia serviços críticos
net stop "Windows Audio" & net start "Windows Audio"