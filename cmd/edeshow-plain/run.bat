@echo off
go run -mod=vendor test_plainclient.go
echo exit code: %ERRORLEVEL%
pause