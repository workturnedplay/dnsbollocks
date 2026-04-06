@echo off
setlocal enabledelayedexpansion

rem I put custom Go in PATH
set "goexe=go.exe"
rem set "goexe=D:\custom-go\go\bin\go.exe"
if NOT "%1" == "silent" (
  echo Using GO exe as: %goexe%
  "%goexe%" version
  set | findstr GO
)
rem shouldn't see anything other than GOPATH being set, if GOROOT is set then we've a problem for gcc might use it?! unsure


:: 0. Capture Workspace State
:: Run this BEFORE you 'set GOWORK=off' if you want to know the original state
set "WS_PATH="
for /f "tokens=*" %%w in ('go env GOWORK') do set "WS_PATH=%%w"

:: If WS_PATH is "off" or empty, we aren't in a workspace.
:: Otherwise, WS_PATH contains the full path to your go.work file.
if NOT "!WS_PATH!"=="off" if NOT "!WS_PATH!"=="" (
    set "HAS_WORKSPACE=1"
    if NOT "%1" == "silent" (
      rem Extract the directory from the full file path
      echo Detected Workspace: !WS_PATH!
    )
) else (
    set "HAS_WORKSPACE=0"
)

::if exist "..\go.work" (
if "!HAS_WORKSPACE!"=="1" (
  set "MOD_FLAG="
  if NOT "%1" == "silent" (
    echo Running unvendored due to workspace
  )
) else (
  rem Use vendor ONLY if we are NOT in a workspace
  set "MOD_FLAG=-mod=vendor"
  if NOT "%1" == "silent" (
    echo Running vendored due to lack of workspace
    rem This is the long-form flag the linter actually understands
  )
  set "LINT_MOD_FLAG=--modules-download-mode=vendor"
)


echo Running go vet...
:: ./... means “Walk the directory tree from here, find every Go package, and apply vet to each.”
:: 'go vet' does:
:: Full static analysis of the package
:: Including unreachable code
:: Including dead branches
:: Including code not exercised by tests
::go vet -mod=vendor ./...
"%goexe%" vet !MOD_FLAG! ./cmd/dnsbollocks ./internal/dnsbollocks
if errorlevel 1 goto :fail

echo Running go vet for shadowing ...
set "shade=%USERPROFILE%\go\bin\shadow.exe"
:: Check if shadow.exe exists, if not, install it
if not exist "%shade%" (
    echo [!] shadow.exe not found. Installing via go install...
    "%goexe%" install golang.org/x/tools/go/analysis/passes/shadow/cmd/shadow@latest
    
    :: Double check if installation actually succeeded
    if not exist "%shade%" (
        echo [ERROR] Failed to install shadow analyzer. Check your internet/DNS.
        exit /b 1
    )
)
"%goexe%"  vet -vettool="%shade%" ./cmd/dnsbollocks ./internal/dnsbollocks
if errorlevel 1 goto :fail

echo Running go vet on everything...
"%goexe%" vet !MOD_FLAG! ./...
if errorlevel 1 goto :fail
rem -m: print inlining decisions and some escape-analysis notes.
rem -m repeated (or -m -m): produces more detailed output (extra reasons, stack/heap decision details).
"%goexe%" build -x -gcflags=all="-m -m" !BUILD_WITH_RACE_DETECTOR! !MOD_FLAG! -o bin\dnsbollocks.exe ./cmd/dnsbollocks >dnsbollocks.escape.log 2>&1
"%goexe%" build !BUILD_WITH_RACE_DETECTOR! !MOD_FLAG! -o bin\dnsbollocks.exe ./cmd/dnsbollocks
rem go.exe build !MOD_FLAG! -o bin\dnsbollocks.exe ./cmd/dnsbollocks
if errorlevel 1 goto :fail

set "lintexe=%USERPROFILE%\go\bin\golangci-lint.exe"
echo Running %lintexe%
"%lintexe%" run !LINT_MOD_FLAG! ./...
if errorlevel 1 goto :fail

rem echo Running: go build ... 
rem "%goexe%" build !MOD_FLAG! -o bin\dnsbollocks.exe ./cmd/dnsbollocks
rem if errorlevel 1 goto :fail

echo Check succeeded.
pause
goto :eof

:fail
echo.
echo *** CHECK FAILED ***
pause
exit /b 1

