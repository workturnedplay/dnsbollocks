@echo off
setlocal enabledelayedexpansion

:: Use vendor ONLY if we are NOT in a workspace
set "MOD_FLAG=-mod=vendor"
if exist "..\go.work" (
set "MOD_FLAG="
echo Running unvendored
) else (
echo Running vendored
)

::if running as admin must get back to current dir:
cd /d %~dp0

::echo Cleaning Go cache
::go clean -cache -modcache
::if errorlevel 1 goto :fail

echo Running go vet...
:: ./... means “Walk the directory tree from here, find every Go package, and apply vet to each.”
:: 'go vet' does:
:: Full static analysis of the package
:: Including unreachable code
:: Including dead branches
:: Including code not exercised by tests
::go vet -mod=vendor ./...
::go vet -mod=vendor -unsafeptr=false
go vet !MOD_FLAG! -unsafeptr=false ./...
if errorlevel 1 goto :fail

echo Running go build
go build !MOD_FLAG! .
if errorlevel 1 goto :fail

echo Running go test
go test !MOD_FLAG! -v
if errorlevel 1 goto :fail

echo all succeeded.
pause
goto :eof

:fail
echo.
echo *** something FAILED ***
pause
exit /b 1