@echo off
go version
go build
echo exit code: %ERRORLEVEL%
pause