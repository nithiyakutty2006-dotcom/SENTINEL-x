@echo off
cd /d "%~dp0"
title SENTINEL-X 2.0 - AI Security Operations Center
color 0B

echo ======================================================================
echo   SENTINEL-X 2.0 - AI-Based Network Security Monitoring System
echo ======================================================================
echo.
echo [1/3] Verifying Python Environment...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not found in PATH! Please install Python 3.9+ and add it to PATH.
    pause
    exit /b 1
)

echo [2/3] Checking Dependencies...
pip install -r requirements.txt

echo.
echo [3/3] Launching Web Application on http://127.0.0.1:8000 ...
echo ======================================================================
echo   Open your browser and navigate to: http://127.0.0.1:8000
echo   Sign in with an account configured for this database.
echo ======================================================================
echo.

start "" cmd /c "timeout /t 3 /nobreak >nul && start http://127.0.0.1:8000"
python main.py

pause
