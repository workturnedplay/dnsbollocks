@echo off
break off

if "%__CHILD__%"=="" (
  rem re-launch self as non-interactive child that will do the work
  set "__CHILD__=1"
  rem start "" /b cmd /c "%~f0" %*
  start "" cmd /c "%~f0" %*
  exit /b
)

rem --- child instance: place your real work below ---
rem Example long-running loop
rem for /l %%i in (1,1,1000000) do (
rem   echo %%i
rem   ping -n 2 127.0.0.1 >nul
rem )



title DNS Proxy Runner
setlocal enabledelayedexpansion

echo Starting DNS Proxy...
rem .\dns-proxy.exe
cmd /c "%~dp0dns-proxy.exe" %*
rem powershell -NoProfile -Command "Start-Process -FilePath '%~dp0dns-proxy.exe' -ArgumentList '%*' -NoNewWindow"

REM Check errorlevel from exe exit (0 normal, 1 fail)
if !errorlevel! neq 0 (
    echo Exe exited with error !errorlevel! - press any key to continue
    pause >nul
    exit /b !errorlevel!
)

echo Exe exited normally - press any key to exit
pause >nul
