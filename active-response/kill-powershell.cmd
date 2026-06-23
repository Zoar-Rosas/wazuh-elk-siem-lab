@echo off
setlocal enableextensions enabledelayedexpansion

rem Registro de auditoría para el SOC
set LOG_FILE="%PROGRAMFILES(X86)%\ossec-agent\active-response\active-responses.log"

echo ========================================= >> %LOG_FILE%
echo [%DATE% %TIME%] ¡ALERTA! Intento de fuerza bruta local detectado (Regla 100002). >> %LOG_FILE%
echo [%DATE% %TIME%] Iniciando contención activa de terminales... >> %LOG_FILE%

rem Matamos de forma fulminante cualquier consola local abierta donde se pueda estar ejecutando el ataque
echo [%DATE% %TIME%] Cerrando instancias de PowerShell... >> %LOG_FILE%
taskkill /F /IM powershell.exe /T >> %LOG_FILE% 2>&1

echo [%DATE% %TIME%] Cerrando instancias de CMD... >> %LOG_FILE%
taskkill /F /IM cmd.exe /T >> %LOG_FILE% 2>&1

echo [%DATE% %TIME%] Defensa completada. Consolas locales mitigadas. >> %LOG_FILE%
exit /b 0