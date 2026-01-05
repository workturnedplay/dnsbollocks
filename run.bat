@echo off
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
@echo on
%~dp0\dnsbollocks.exe
pause