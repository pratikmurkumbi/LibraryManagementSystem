@echo off
setlocal
cd /d "%~dp0"
title Government Polytechnic Haliyal - Library Management System

if not exist ".venv\Scripts\python.exe" (
    echo Creating Python virtual environment...
    py -3 -m venv .venv
    if errorlevel 1 python -m venv .venv
)

if not exist ".venv\Scripts\python.exe" (
    echo Could not create the Python environment.
    echo Please install Python 3 and try again.
    pause
    exit /b 1
)

call ".venv\Scripts\activate.bat"
python -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo Installing required Python packages...
    python -m pip install -r requirements.txt
    if errorlevel 1 (
        echo.
        echo Package installation failed. If this PC is offline, connect it to the internet once and run this file again.
        pause
        exit /b 1
    )
)

python -m py_compile app.py
if errorlevel 1 (
    echo app.py has a Python syntax error. Startup cancelled.
    pause
    exit /b 1
)

echo.
echo Starting Government Polytechnic Haliyal Library Management System...
start "" "http://127.0.0.1:5000"
python app.py
pause
endlocal
