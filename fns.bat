@echo off
cd /d %~dp0
set PYTHON=%~dp0.venv\Scripts\python.exe

if "%1"=="" (
    echo Usage: fns.bat [run^|daemon] [options]
    echo   run    - Run pipeline once
    echo   daemon - Start periodic daemon
    echo.
    echo Example:
    echo   fns.bat run -v -n 10
    echo   fns.bat daemon -i 3
    exit /b 1
)

%PYTHON% -m fns -c "%~dp0fns.yaml" %*
