@echo off
if "%~1"=="" (
    echo Usage: start.bat ^<interval_hours^>
    echo Example: start.bat 2
    exit /b 1
)

set INTERVAL=%~1
set SCRIPT_DIR=%~dp0

echo Starting v2rayN...
start "" "C:\Users\user\Documents\v2rayN-windows-64-desktop\v2rayN-windows-64\v2rayN.exe"

echo Waiting 5 seconds for v2rayN to initialize...
ping 127.0.0.1 -n 6 >nul

echo Starting FreeNodeSeeker daemon with interval %INTERVAL% hours...
call "%SCRIPT_DIR%fns.bat" daemon -i %INTERVAL%
