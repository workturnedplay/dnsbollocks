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
echo Running %cmd%
%cmd%
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
