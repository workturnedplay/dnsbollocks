@echo off
set "GITBASH=C:\Program Files\Git\git-bash.exe"

start "" /b "%GITBASH%" -c "tail -f queries.log"

