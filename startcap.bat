@echo off
rem 1. Prevent the current working directory from taking precedence over PATH, doesn't work with eg. "start go.exe"
set "NoDefaultCurrentDirectoryInExePath=1"
cd /d "%~dp0"

netsh trace start capture=yes scenario=InternetClient
echo press to stop it
pause
netsh trace stop
pause