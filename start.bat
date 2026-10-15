@echo off
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
  py -3 -m venv .venv
  if errorlevel 1 goto fail
)
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto fail
if not exist .env (
  .venv\Scripts\python.exe setup_guard.py
  if errorlevel 1 goto fail
)
.venv\Scripts\python.exe server.py
:fail
pause
