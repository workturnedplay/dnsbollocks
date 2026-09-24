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

rem https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts

rem Download to a temporary file to prevent partial overwrites
curl --ssl-revoke-best-effort -o hosts.tmp https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts
if errorlevel 1 goto :fail

rem Safely replace the existing file only after a successful download
move /y hosts.tmp hosts >nul
if errorlevel 1 goto :fail

echo "all done"
pause
goto :eof
::goto :eof means: return from the current batch context
::If you’re in the main script, it exits the script
::If you’re inside a called batch or subroutine, it returns to the caller

:fail
rem Clean up the temporary file if it exists
if exist hosts.tmp del hosts.tmp

echo.
echo *** DOWNLOAD FAILED ***
pause
exit /b 1
