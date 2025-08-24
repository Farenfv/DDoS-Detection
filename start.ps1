# PowerShell script to start DDoS Detection System

Write-Host "Starting DDoS Detection System..." -ForegroundColor Green
Write-Host ""

# Change to the directory where this script is located
Set-Location -Path $PSScriptRoot

# Check if Python is installed
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✓ Python found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ Error: Python is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install Python 3.8+ and try again" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Check if requirements are installed
Write-Host "Checking dependencies..." -ForegroundColor Yellow
if (Test-Path "requirements.txt") {
    pip install -r requirements.txt
} else {
    Write-Host "Warning: requirements.txt not found in current directory" -ForegroundColor Yellow
    Write-Host "Current directory: $(Get-Location)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Starting application..." -ForegroundColor Green
Write-Host "Web interface will be available at: http://localhost:5000" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop the application" -ForegroundColor Yellow
Write-Host ""

# Start the application
if (Test-Path "ddos_detection.py") {
    python ddos_detection.py
} else {
    Write-Host "Error: ddos_detection.py not found in current directory" -ForegroundColor Red
    Write-Host "Current directory: $(Get-Location)" -ForegroundColor Yellow
    Write-Host "Please ensure you're running this from the correct folder" -ForegroundColor Yellow
}

Read-Host "Press Enter to exit"
