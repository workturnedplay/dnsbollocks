@echo off
rem 1. Prevent the current working directory from taking precedence over PATH, doesn't work with eg. "start go.exe"
set "NoDefaultCurrentDirectoryInExePath=1"

::if running as admin must get back to current dir:
:: 1. Change directory and store path BEFORE enabling delayed expansion.
::    While delayed expansion is disabled, '!' is treated as a literal character.
setlocal disabledelayedexpansion
:: ^ needed if called by a 'call me.bat' command where it's already enabled in parent!
cd /d "%~dp0"
set "SCRIPT_DIR=%~dp0"

:: 2. Enable delayed expansion for script logic
setlocal enabledelayedexpansion

:: 3. Test: Use !SCRIPT_DIR! (safe), do NOT use %SCRIPT_DIR% or %~dp0 (unsafe)
rem echo Current DIR: "!SCRIPT_DIR!"

certutil -dump cert.pem
echo Note, it only works when dnsbollocks is listening on this IP:
certutil -dump cert.pem|findstr "IP Address"
::echo You would have to delete cert.pem if you change the listen_doh IP in the config.json for the cert(and key.pem) to be regenerated and thus to work when a client tries to connect.
echo Running dnsbollocks will auto-regen the cert if the IP or host doesn't match the 'listen_doh' IP(or host) setting from config.json
pause