@echo off
go run -mod=vendor test_dohclient.go
echo exit code: %ERRORLEVEL%
pause