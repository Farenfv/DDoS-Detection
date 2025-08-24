@echo off
echo Starting DDoS Detection System...
echo.

REM Change to the directory where this batch file is located
cd /d "%~dp0"

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
if exist requirements.txt (
    pip install -r requirements.txt
) else (
    echo Warning: requirements.txt not found in current directory
    echo Current directory: %CD%
)

echo.
echo Starting application...
echo Web interface will be available at: http://localhost:5000
echo Press Ctrl+C to stop the application
echo.

if exist ddos_detection.py (
    python ddos_detection.py
) else (
    echo Error: ddos_detection.py not found in current directory
    echo Current directory: %CD%
    echo Please ensure you're running this from the correct folder
)

pause
