@echo off
echo Starting DDoS Detection System...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.8+ and try again
    pause
    exit /b 1
)

REM Check if requirements are installed
echo Checking dependencies...
pip install -r requirements.txt

echo.
echo Starting application...
echo Web interface will be available at: http://localhost:5000
echo Press Ctrl+C to stop the application
echo.

python ddos_detection.py

pause
