@echo off
go run -mod=vendor spy.go
echo exit code: %ERRORLEVEL%
pause