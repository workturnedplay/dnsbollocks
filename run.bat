@echo off
@rem set GOMAXPROCS=12

@rem set CGO_ENABLED=1
@rem go run -race main.go

@rem pause
echo "Current working directory is:"
cd
echo "Script is running from %~dp0"
cd %~dp0
echo "Current(changed) working directory is:"
cd
@rem .\dnsbollocks.exe

@rem %~dp0 already has the end \ but adding another one for visibility:
@echo on
%~dp0\dnsbollocks.exe
pause