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
set "GIT_BASH=%ProgramFiles%\Git\git-bash.exe"
if not exist "%GIT_BASH%" set "GIT_BASH=%ProgramFiles(x86)%\Git\git-bash.exe"
if not exist "%GIT_BASH%" goto :no_git_bash
set "BASH_DIR=%SCRIPT_DIR:\=/%"
set "BASH_DIR=%BASH_DIR::=%"
set "BASH_DIR=/%BASH_DIR%"
start "Clash Auto Select" "%GIT_BASH%" -lc "cd '%BASH_DIR%' && bash clash_auto_select.sh"
goto :after_auto_select
:no_git_bash
start "Clash Auto Select" cmd /k ""%SCRIPT_DIR%clash_auto_select.bat""
:after_auto_select
echo Clash auto-select log: %SCRIPT_DIR%logs\clash_auto_select.log

echo Starting FreeNodeSeeker daemon with interval %INTERVAL% hours...
call "%SCRIPT_DIR%fns.bat" daemon -i %INTERVAL%
