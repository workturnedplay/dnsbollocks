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

go run !MOD_FLAG! .
echo exit code: %ERRORLEVEL%
pause