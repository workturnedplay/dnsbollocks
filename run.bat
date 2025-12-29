@echo off
@rem set GOMAXPROCS=12

.\dns-proxy.exe
@rem set CGO_ENABLED=1
@rem go run -race main.go

pause
