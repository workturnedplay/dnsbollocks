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

:: 1. Setup your base flags
set "LDFLAGS_HARDENED="
set "CGO_SETTING=0"

:: 2. Logic Check: If RACE is NOT set, we can use Internal Hardening
if "!BUILD_WITH_RACE_DETECTOR!"=="" (
    rem disregard this, Gemini 3 Fast is hallucinating or something:
    rem Control Flow Guard (CFG) doesn't work if CGO_ENABLED=1 is set like when 'go build -race' for example.
    rem -ldflags="-linkmode=internal -extldflags=-Wl,--high-entropy-va"
    rem "(Go 1.21+ on Win11 enables High Entropy VA automatically for 64-bit)." - gemini 3 fast
    rem XXX: i say this -extldflags is useless because extldflags is ignored when CGO_ENABLED=0 plus it's using -ldflags=-linkmode=internal
    rem set "LDFLAGS_HARDENED=-ldflags=-linkmode=internal -extldflags=-Wl,--high-entropy-va"
    rem nevermind all that from above!
    set "CGO_SETTING=0"
) else (
    :: If RACE is enabled, we MUST use CGO and External Linking
    rem set "LDFLAGS_HARDENED="
    rem -mguard=cf (Control Flow Guard) - this is truth!
    rem the following 2, fail like: ==1360==ERROR: ThreadSanitizer failed to allocate 0x000004cd0000 (80543744) bytes at 0x100ef9cb40000 (error code: 87) 
    rem this overwrote the mguard setting:
    rem set "LDFLAGS_HARDENED=-ldflags=-linkmode=external -extldflags=-mguard=cf -extldflags=-Wl,--high-entropy-va"
    rem set "LDFLAGS_HARDENED=-ldflags=-linkmode=external -extldflags=-Wl,--high-entropy-va"
    rem This won't link:
    rem set "LDFLAGS_HARDENED=-ldflags=-linkmode=external -extldflags=-mguard=cf"
    rem This is bad args to link.exe:
    rem set "LDFLAGS_HARDENED=-ldflags=-linkmode=external -extldflags=-mguard=cf -Wl,--high-entropy-va"
    rem nevermind all that from above! Geminit 3 flash must be toying with me!
    set "CGO_SETTING=1"
)
set "CGO_ENABLED=!CGO_SETTING!"
echo using CGO_ENABLED=!CGO_ENABLED!


rem -m: print inlining decisions and some escape-analysis notes.
rem -m repeated (or -m -m): produces more detailed output (extra reasons, stack/heap decision details).
rem XXX: disabled, not needed anymore (bug fixed in Go v1.26.2)
rem "%goexe%" build -x -gcflags=all="-m -m" !BUILD_WITH_RACE_DETECTOR! !MOD_FLAG! -o bin\dnsbollocks.exe ./cmd/dnsbollocks >dnsbollocks.escape.log 2>&1
rem go build -trimpath: Removes your local file paths (like c:\cust-Go\...) from the binary. Great for privacy/security.
rem -ldflags="-s -w" : Strips debug information and the symbol table. Makes the EXE smaller and harder to reverse-engineer.
rem "%goexe%" build "!LDFLAGS_HARDENED!" !BUILD_WITH_RACE_DETECTOR! !MOD_FLAG! -o bin\dnsbollocks.exe ./cmd/dnsbollocks
rem if errorlevel 1 goto :fail
"%goexe%" build !BINCOMPARE! !BUILD_WITH_RACE_DETECTOR! !MOD_FLAG! -o bin\dnsbollocks.exe ./cmd/dnsbollocks
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

