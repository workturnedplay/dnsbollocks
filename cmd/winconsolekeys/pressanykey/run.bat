@echo off
go run -mod=vendor try.go
echo exit code: %ERRORLEVEL%
pause