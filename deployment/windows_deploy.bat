@echo off
TITLE AI-Driven DDoS Detection & Mitigation Framework - Deployment
COLOR 0B
echo ======================================================================
echo    AI-DRIVEN DDOS DETECTION & AUTOMATED MITIGATION IN SDN
echo                 WINDOWS AUTOMATED DEPLOYMENT
echo ======================================================================
echo.

:: 1. Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.10+ from https://www.python.org/
    pause
    exit /b 1
)
echo [OK] Python found:
python --version

:: 2. Check Node.js
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Node.js is not installed or not in PATH.
    echo Please install Node.js 18+ from https://nodejs.org/
    pause
    exit /b 1
)
echo [OK] Node.js found:
node --version
echo.

:: 3. Setup Virtual Environment
if not exist "venv" (
    echo [*] Creating virtual environment (venv)...
    python -m venv venv
)
echo [*] Activating virtual environment...
call .\venv\Scripts\activate.bat

:: 4. Install Python dependencies
echo [*] Checking Python dependencies...
pip install -r requirements.txt --quiet
echo [OK] Python dependencies verified.

:: 5. Install Frontend dependencies
if not exist "dashboard\node_modules" (
    echo [*] Installing Dashboard dependencies (npm install)...
    cd dashboard
    call npm install
    cd ..
)
echo [OK] Dashboard dependencies verified.
echo.

:: 6. Launch Unified Framework
echo ======================================================================
echo Launching Full Framework:
echo   - FastAPI Backend (http://127.0.0.1:8000)
echo   - React Dashboard (http://localhost:3000)
echo   - SDN Switch & Continuous Detection Engine
echo ======================================================================
echo.
python run_system.py
pause
