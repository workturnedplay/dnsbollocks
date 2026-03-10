@echo off

:: (nope:)disallow Ctrl+break, no effect, it still prompts: Terminate batch job (Y/N)?
::break off
::so, break off:
::Does not disable Ctrl+Break
::Does not prevent interruption
::Does not affect Ctrl+C at all
::Only controls whether Ctrl+Break sets the internal BREAK flag
::That flag is checked by certain batch commands (FOR, COPY, etc.) to decide whether to abort early.


:: ctrl+c is trapped by our .exe by putting the terminal in raw mode, thus this .bat won't sense it and ask to terminate batch job.

setlocal EnableExtensions EnableDelayedExpansion

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

@rem set GOMAXPROCS=12

@rem set CGO_ENABLED=1
@rem go run -race main.go

@rem pause
echo "Current working directory is:"
cd
echo "Script is running from %~dp0"
cd /d %~dp0
:: What %~dp0 actually is
:: %0 → the path used to launch the script
:: ~d → drive letter
:: ~p → path (ending with a backslash)
::
:: cd /d changes the driver letter too
:: "Use the /D switch to change current drive in addition to changing current directory for a drive."

echo "Current(changed) working directory is:"
cd
@rem .\dnsbollocks.exe

@rem %~dp0 already has the end \ but adding another one for visibility:
:run
set cmd="%~dp0\bin\dnsbollocks.exe"
:: Check if the file actually exists first
if not exist "%cmd%" (
    echo Error: Could not find %cmd%
    pause
    exit /b
)
echo Running %cmd%
echo Requesting elevation for %cmd%...
powershell -Command "Start-Process -FilePath '%cmd%' -WorkingDirectory '%~dp0' -Verb RunAs"
::powershell -Command "Start-Process cmd -ArgumentList '/k \"\"%cmd%\"\"' -Verb RunAs"
rem %cmd%
set "ec=%ERRORLEVEL%"

if "!ec!"=="130" (
    echo "dnsbollocks exited with code 130 (sigint) - which to this bat file means we should be restarting it... (use alt+x to not do this next time)"
    goto run
)

if "!ec!"=="0" (
    echo dnsbollocks finished successfully.
) else (
    echo dnsbollocks exited with error code !ec!
)
pause
