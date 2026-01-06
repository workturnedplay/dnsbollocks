@echo off
setlocal

cd /d "%~dp0"

::echo Running go vet ... (not here, we do this in build.bat)
::go.exe vet -mod=vendor ./...
::if errorlevel 1 goto :fail

echo Running go test 
:: go test runs a limited 'go vet' only on reachable code paths relevant to the package ...
:: so a full 'go vet' might fail even if 'go test' 's internal run of 'go vet' does not!
go.exe test -mod=vendor ./...
:: ./... means “Walk the directory tree from here, find every Go package, and apply vet to each.”
if errorlevel 1 goto :fail

::go.exe test -mod=vendor ./cmd/dnsbollocks
::pause

echo Tests succeeded.
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
