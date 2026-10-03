@echo off
TITLE Docker Deployment - AI-Driven DDoS SDN Framework
COLOR 0A
echo ======================================================================
echo    AI-DRIVEN DDOS DETECTION & AUTOMATED MITIGATION IN SDN
echo                 DOCKER COMPOSE DEPLOYMENT
echo ======================================================================
echo.

docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker is not installed or Docker daemon is not running.
    echo Please install Docker Desktop from https://www.docker.com/
    pause
    exit /b 1
)

echo [*] Building and launching containers in detached mode...
docker compose up --build -d

echo.
echo [OK] Containers started successfully!
echo   - Dashboard UI:  http://localhost:3000
echo   - FastAPI API:   http://localhost:8000
echo   - Swagger Docs:  http://localhost:8000/docs
echo.
echo Showing live logs (Press Ctrl+C to exit logs):
docker compose logs -f
