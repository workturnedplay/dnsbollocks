@echo off
:: avoid https://github.com/golang/go/issues/51654
set GOMAXPROCS=12

.\dns-proxy.exe

pause
