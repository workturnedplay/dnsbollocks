@echo off
setlocal enabledelayedexpansion

rem I put custom Go in PATH
set "goexe=go.exe"
rem set "goexe=D:\custom-go\go\bin\go.exe"
echo Using GO exe as: %goexe%
"%goexe%" version
set | findstr GO
rem shouldn't see anything other than GOPATH being set, if GOROOT is set then we've a problem for gcc might use it?! unsure

REM :: 0. Capture Workspace State
REM :: Run this BEFORE you 'set GOWORK=off' if you want to know the original state
REM set "WS_PATH="
REM for /f "tokens=*" %%w in ('go env GOWORK') do set "WS_PATH=%%w"

REM :: If WS_PATH is "off" or empty, we aren't in a workspace.
REM :: Otherwise, WS_PATH contains the full path to your go.work file.
REM if NOT "!WS_PATH!"=="off" if NOT "!WS_PATH!"=="" (
    REM set "HAS_WORKSPACE=1"
    REM :: Extract the directory from the full file path
    REM echo Detected Workspace: !WS_PATH!
REM ) else (
    REM set "HAS_WORKSPACE=0"
REM )

REM set "HAS_WORKSPACE=0"

REM if "!HAS_WORKSPACE!"=="1" (
  REM set "MOD_FLAG="
  REM echo Running unvendored due to workspace
REM ) else (
  REM :: Use vendor ONLY if we are NOT in a workspace
  REM set "MOD_FLAG=-mod=vendor"
  REM echo Running vendored due to lack of workspace
REM )

echo Running vendored
set "MOD_FLAG=-mod=vendor"

call prebuildcheck.bat silent
if errorlevel 1 (
    echo.
    choice /c NY /m "%lintexe% found issues. Stop build?"
    if errorlevel 2 goto :fail
)

rem -m: print inlining decisions and some escape-analysis notes.
rem -m repeated (or -m -m): produces more detailed output (extra reasons, stack/heap decision details).
"%goexe%" build -x -gcflags=all="-m -m" !BUILD_WITH_RACE_DETECTOR! !MOD_FLAG! -o bin\dnsbollocks.exe ./cmd/dnsbollocks >dnsbollocks.escape.log 2>&1
"%goexe%" build !BUILD_WITH_RACE_DETECTOR! !MOD_FLAG! -o bin\dnsbollocks.exe ./cmd/dnsbollocks
rem go.exe build !MOD_FLAG! -o bin\dnsbollocks.exe ./cmd/dnsbollocks
if errorlevel 1 goto :fail

echo Build succeeded.
pause
goto :eof

:fail
echo.
echo *** BUILD FAILED ***
pause
exit /b 1

