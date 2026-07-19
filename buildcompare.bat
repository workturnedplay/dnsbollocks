@echo off
rem 1. Prevent the current working directory from taking precedence over PATH, doesn't work with eg. "start go.exe"
set "NoDefaultCurrentDirectoryInExePath=1"
cd /d "%~dp0"

rem set "BINCOMPARE=-ldflags=-s -w"
rem set "BINCOMPARE=@buildcompare.args" hallucinated by Gemini
rem set "BINCOMPARE=-trimpath -ldflags='-buildid= -s -w'"
set BINCOMPARE=-trimpath "-ldflags=-s -w -buildid="
call .\buildwrace.bat
pause