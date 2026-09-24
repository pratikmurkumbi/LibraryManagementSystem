@echo off
setlocal
cd /d "%~dp0"
title Government Polytechnic Haliyal - Digital Library
if not exist ".venv\Scripts\python.exe" (
  echo Creating virtual environment...
  py -3 -m venv .venv
  if errorlevel 1 python -m venv .venv
)
call ".venv\Scripts\activate.bat"
python -m pip install -r requirements.txt
if not exist "library.db" (
  python -c "from database.database import init_database; init_database()"
)
echo.
echo Starting Digital Library...
start "" "http://127.0.0.1:5000"
python app.py
endlocal
