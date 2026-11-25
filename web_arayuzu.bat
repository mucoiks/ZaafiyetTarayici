@echo off
chcp 65001 >nul
set PYTHONUTF8=1
setlocal
cd /d "%~dp0"
title Otomatik Zafiyet Tarayici - Web Arayuzu

if exist "%~dp0venv\Scripts\python.exe" (
    "%~dp0venv\Scripts\python.exe" "%~dp0web_app.py" --open
) else (
    python "%~dp0web_app.py" --open
)
pause
