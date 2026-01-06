@echo off
setlocal

echo Running go vet...
:: ./... means “Walk the directory tree from here, find every Go package, and apply vet to each.”
:: 'go vet' does:
:: Full static analysis of the package
:: Including unreachable code
:: Including dead branches
:: Including code not exercised by tests
go vet ./...
if errorlevel 1 goto :fail

go.exe build -mod=vendor -o bin\dnsbollocks.exe ./cmd/dnsbollocks
if errorlevel 1 goto :fail

echo Build succeeded.
pause
goto :eof

:fail
echo.
echo *** BUILD FAILED ***
pause
exit /b 1

