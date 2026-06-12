@echo off
cd /d %~dp0
call .venv\Scripts\activate.bat
fns run -n 10 -v
pause
