@echo off
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe python -m venv .venv
.venv\Scripts\python -m pip install -q -r requirements.txt
if errorlevel 1 (
    echo Kurulum basarisiz, Python 3.10+ kurulu mu?
    pause
    exit /b 1
)
start "" cmd /c "timeout /t 3 >nul & start http://127.0.0.1:8003"
.venv\Scripts\python -m uvicorn src.api:app --host 127.0.0.1 --port 8003
