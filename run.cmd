@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo ERROR: Create .venv and install requirements.txt first. 1>&2
  exit /b 1
)
".venv\Scripts\python.exe" "monitor.py" --config "config.json" check %*
exit /b %errorlevel%
