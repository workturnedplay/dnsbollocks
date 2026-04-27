@echo off
go version
del tmpnocomments.go
go fmt
go build
go run -- main.go  -o tmpnocomments.go "../../internal/dnsbollocks/platform_windows.go"
echo exit code: %ERRORLEVEL%
pause