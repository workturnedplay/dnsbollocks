@echo off
setlocal enabledelayedexpansion

:: 0. Capture Workspace State
:: Run this BEFORE you 'set GOWORK=off' if you want to know the original state
set "WS_PATH="
for /f "tokens=*" %%w in ('go env GOWORK') do set "WS_PATH=%%w"

:: If WS_PATH is "off" or empty, we aren't in a workspace.
:: Otherwise, WS_PATH contains the full path to your go.work file.
if NOT "!WS_PATH!"=="off" if NOT "!WS_PATH!"=="" (
    set "HAS_WORKSPACE=1"
    :: Extract the directory from the full file path
    echo Detected Workspace: !WS_PATH!
) else (
    set "HAS_WORKSPACE=0"
)

::if exist "..\go.work" (
if "!HAS_WORKSPACE!"=="1" (
  set "MOD_FLAG="
  echo Running unvendored due to workspace
) else (
  :: Use vendor ONLY if we are NOT in a workspace
  set "MOD_FLAG=-mod=vendor"
  echo Running vendored due to lack of workspace
)


cd /d "%~dp0"

::echo Running go vet ... (not here, we do this in build.bat)
::go.exe vet -mod=vendor ./...
::if errorlevel 1 goto :fail

echo Running go test 
:: go test runs a limited 'go vet' only on reachable code paths relevant to the package ...
:: so a full 'go vet' might fail even if 'go test' 's internal run of 'go vet' does not!
go.exe test -v !MOD_FLAG! ./...
:: ./... means “Walk the directory tree from here, find every Go package, and apply vet to each.”
if errorlevel 1 goto :fail
echo Those tests succeeded.

echo Compiling firewall-requiring ^(ie. Portmaster-ready^) test binary...
rem :: We add "-tags portmaster" here so Go includes the hidden test file
go.exe test -c !MOD_FLAG! -tags portmasterFirewalled -o dev_dns_test.exe .\internal\dnsbollocks\
if %ERRORLEVEL% equ 0 (
    echo Running only the firewall-requiring^(localhost talk^) tests...
    .\dev_dns_test.exe -test.v -test.run "^TestFWNeeded"
    if errorlevel 1 (
      echo You will have to allow "127.0.0.1 tcp/49152-65535" in firewall^(eg. portmaster^) both IN and OUT for these tests to pass
      goto :fail
    )
) else (
    echo Compilation failed.
    goto :fail
)

::go.exe test -mod=vendor ./cmd/dnsbollocks
::pause

echo All tests succeeded.
pause
goto :eof
::goto :eof means: return from the current batch context
::If you’re in the main script, it exits the script
::If you’re inside a called batch or subroutine, it returns to the caller

:fail
echo.
echo *** TESTS FAILED ***
pause
exit /b 1
