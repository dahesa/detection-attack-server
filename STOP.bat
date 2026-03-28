@echo off
echo ========================================
echo Zein Security WAF - Stop All Services
echo ========================================
echo.

echo [1/2] Stopping all application processes...
taskkill /F /IM node.exe 2>nul
if %errorlevel% equ 0 (
    echo   [OK] Node.js processes stopped
) else (
    echo   [INFO] No Node.js processes found
)

taskkill /F /IM python.exe 2>nul
if %errorlevel% equ 0 (
    echo   [OK] Python processes stopped
) else (
    echo   [INFO] No Python processes found
)

taskkill /F /IM py.exe 2>nul
if %errorlevel% equ 0 (
    echo   [OK] Python (py) processes stopped
) else (
    echo   [INFO] No Python (py) processes found
)

taskkill /F /IM go.exe 2>nul
if %errorlevel% equ 0 (
    echo   [OK] Go processes stopped
) else (
    echo   [INFO] No Go processes found
)

timeout /t 2 /nobreak >nul
echo.

echo [2/2] Stopping Docker services...
docker-compose stop mysql redis 2>nul
if %errorlevel% equ 0 (
    echo   [OK] Docker services stopped
) else (
    echo   [INFO] Docker services may not be running
)
echo.

echo ========================================
echo All services stopped!
echo ========================================
echo.
echo To remove Docker containers and volumes:
echo   docker-compose down -v
echo.
pause
