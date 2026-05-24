@echo off
go version
del tmpnocomments.go 2>nul
go fmt
go build
go run -- main.go  -o tmpnocomments.go "../../internal/dnsbollocks/platform_windows.go"
echo exit code: %ERRORLEVEL%
pause