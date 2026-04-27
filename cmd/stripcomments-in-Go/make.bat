@echo off
go version
del tmpnocomments.go
go build
echo exit code: %ERRORLEVEL%
pause