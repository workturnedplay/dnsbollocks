@echo off
rem 1. Prevent the current working directory from taking precedence over PATH, doesn't work with eg. "start go.exe"
set "NoDefaultCurrentDirectoryInExePath=1"
cd /d "%~dp0"

set "GITBASH=C:\Program Files\Git\git-bash.exe"

start "" /b "%GITBASH%" -c "tail -f queries.log"

