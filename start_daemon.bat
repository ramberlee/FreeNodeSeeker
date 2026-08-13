@echo off
if "%~1"=="" (
    echo Usage: start.bat ^<interval_hours^>
    echo Example: start.bat 2
    exit /b 1
)

set INTERVAL=%~1
set SCRIPT_DIR=%~dp0

echo Starting clash-verge...
start "" "D:\Program Files\Clash Verge\clash-verge.exe"

echo Waiting 5 seconds for clash-verge to initialize...
ping 127.0.0.1 -n 6 >nul

set "PYTHON=%SCRIPT_DIR%.venv\Scripts\python.exe"
if not exist "%PYTHON%" set "PYTHON=python"

echo Starting clash auto-select...
start "Clash Auto Select" /min "%PYTHON%" "%SCRIPT_DIR%clash_auto_select.py"

echo Starting FreeNodeSeeker daemon with interval %INTERVAL% hours...
call "%SCRIPT_DIR%fns.bat" daemon -i %INTERVAL%
