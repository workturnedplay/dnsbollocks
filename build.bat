@echo off
setlocal

echo Running go vet...
:: ./... means “Walk the directory tree from here, find every Go package, and apply vet to each.”
:: 'go vet' does:
:: Full static analysis of the package
:: Including unreachable code
:: Including dead branches
:: Including code not exercised by tests
go vet -mod=vendor ./...
if errorlevel 1 goto :fail

echo Running golangci-lint
golangci-lint run
::if errorlevel 1 goto :fail
if errorlevel 1 (
    echo.
    choice /c NY /m "golangci-lint found issues. Stop build?"
    if errorlevel 2 goto :fail
)

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

