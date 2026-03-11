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

echo Running benchmark
:: go test runs a limited 'go vet' only on reachable code paths relevant to the package ...
:: so a full 'go vet' might fail even if 'go test' 's internal run of 'go vet' does not!
go.exe test !MOD_FLAG! -bench=. -benchtime=5s -benchmem -count=5 ./...
:: ./... means “Walk the directory tree from here, find every Go package, and apply vet to each.”
if errorlevel 1 goto :fail

::go.exe test -mod=vendor ./cmd/dnsbollocks
::pause

echo Bench succeeded.
pause
goto :eof
::goto :eof means: return from the current batch context
::If you’re in the main script, it exits the script
::If you’re inside a called batch or subroutine, it returns to the caller

:fail
echo.
echo *** Benchmark FAILED ***
pause
exit /b 1
