@echo off
setlocal EnableExtensions EnableDelayedExpansion

echo ========================================
echo Zein Security WAF - Start All Services
echo ========================================
echo.

REM Pindah ke folder script
cd /d "%~dp0"

REM ========================================
REM [1/7] Stop old processes
REM ========================================
echo [1/7] Stopping old processes...
taskkill /F /IM node.exe >nul 2>&1
taskkill /F /IM python.exe >nul 2>&1
taskkill /F /IM py.exe >nul 2>&1
taskkill /F /IM go.exe >nul 2>&1
taskkill /F /IM zeinsec-backend.exe >nul 2>&1
timeout /t 2 /nobreak >nul
echo   [OK] Old processes stopped
echo.

REM ========================================
REM [2/7] Check prerequisites
REM ========================================
echo [2/7] Checking prerequisites...

set HAS_DOCKER=0
set HAS_PYTHON=0
set HAS_GO=0
set HAS_NODE=0
set PYTHON_CMD=

where docker >nul 2>&1
if %errorlevel% equ 0 (
    set HAS_DOCKER=1
    echo   [OK] Docker found
) else (
    echo   [WARN] Docker not found
)

where go >nul 2>&1
if %errorlevel% equ 0 (
    set HAS_GO=1
    echo   [OK] Go found
) else (
    echo   [WARN] Go not found - Backend will not start
)

where node >nul 2>&1
if %errorlevel% equ 0 (
    set HAS_NODE=1
    echo   [OK] Node.js found
) else (
    echo   [ERROR] Node.js not found!
    pause
    exit /b 1
)

REM ===== Python detection =====
where py >nul 2>&1
if %errorlevel% equ 0 (
    set HAS_PYTHON=1
    set PYTHON_CMD=py
) else (
    where python >nul 2>&1
    if %errorlevel% equ 0 (
        set HAS_PYTHON=1
        set PYTHON_CMD=python
    ) else (
        where python3 >nul 2>&1
        if %errorlevel% equ 0 (
            set HAS_PYTHON=1
            set PYTHON_CMD=python3
        )
    )
)

if !HAS_PYTHON! equ 1 (
    echo   [OK] Python found: !PYTHON_CMD!
) else (
    echo   [WARN] Python not found - AI Service will not start
)
echo.

REM ========================================
REM [3/7] Start Docker services
REM ========================================
echo [3/7] Starting Docker services...
if !HAS_DOCKER! equ 1 (
    docker-compose up -d mysql redis 2>nul
    if errorlevel 1 (
        echo   [WARN] Docker services may already be running
    ) else (
        echo   [OK] Docker services started
    )
) else (
    echo   [SKIP] Docker not available
)
echo.

REM ========================================
REM [4/7] Wait for database
REM ========================================
echo [4/7] Waiting for database...
if !HAS_DOCKER! equ 1 (
    timeout /t 20 /nobreak >nul
    docker exec zein-mysql mysql -u zein_waf -ppopyalena07 zein_security -e "SELECT 'OK';" >nul 2>&1
    if errorlevel 1 (
        echo   [WARN] Database not ready yet
    ) else (
        echo   [OK] Database connection successful
    )
) else (
    echo   [SKIP] Docker not used
)
echo.

REM ========================================
REM [5/7] Check dependencies
REM ========================================
echo [5/7] Checking dependencies...

if !HAS_PYTHON! equ 1 (
    cd backend\ai-service
    if exist requirements.txt (
        "!PYTHON_CMD!" -m pip show fastapi >nul 2>&1
        if errorlevel 1 (
            echo   [WARN] Python deps not installed - run INSTALL_PYTHON_DEPS.bat
        ) else (
            echo   [OK] Python dependencies ready
        )
    )
    cd ..\..
)

if !HAS_NODE! equ 1 (
    if not exist frontend\node_modules (
        echo   Installing frontend dependencies...
        pushd frontend
        call npm install
        popd
    ) else (
        echo   [OK] Frontend dependencies ready
    )
)
echo.

REM ========================================
REM [6/7] Start services
REM ========================================
echo [6/7] Starting services...

if !HAS_PYTHON! equ 1 (
    echo   Starting AI Service (Python)...
    start "Zein AI Service" cmd /k "cd /d %~dp0backend\ai-service && !PYTHON_CMD! -m uvicorn ai:app --host 0.0.0.0 --port 5000 --reload"
    timeout /t 2 /nobreak >nul
)

if !HAS_GO! equ 1 (
    echo   Starting Backend (Go)...
    cd backend
    if not exist "zeinsec-backend.exe" (
        echo   Building backend executable...
        go build -o zeinsec-backend.exe .
        if errorlevel 1 (
            echo   [WARN] Build failed, will use 'go run' instead
        )
    )
    cd ..
    if exist "%~dp0backend\zeinsec-backend.exe" (
        start "Zein Backend" cmd /k "cd /d %~dp0backend && zeinsec-backend.exe"
    ) else (
        start "Zein Backend" cmd /k "cd /d %~dp0backend && go run ."
    )
    timeout /t 3 /nobreak >nul
)

if !HAS_NODE! equ 1 (
    echo   Starting Frontend (React)...
    start "Zein Frontend" cmd /k "cd /d %~dp0frontend && npm run dev"
)
echo.

REM ========================================
REM [7/7] Done
REM ========================================
echo [7/7] All services started!
echo.
echo ========================================
echo Service URLs:
echo ========================================
if !HAS_PYTHON! equ 1 echo   AI Service:  http://localhost:5000
if !HAS_GO! equ 1     echo   Backend:     http://localhost:8080
if !HAS_NODE! equ 1   echo   Frontend:    http://localhost:3000
echo.
echo ========================================
echo Status:
echo ========================================
echo   - Check the opened windows for service status
echo   - Frontend will open automatically in browser
echo   - Default login: admin / admin123
echo.
echo   Press any key to exit...
pause >nul

echo [7/7] All services started!
echo.
echo ========================================
echo Service URLs:
echo ========================================
if !HAS_PYTHON! equ 1 echo   AI Service:  http://localhost:5000
if !HAS_GO! equ 1     echo   Backend:     http://localhost:8080
if !HAS_NODE! equ 1   echo   Frontend:    http://localhost:3000
echo.
echo ========================================
echo Status:
echo ========================================
echo   - Check the opened windows for service status
echo   - Frontend will open automatically in browser
echo   - Default login: admin / admin123
echo.
echo   Press any key to exit...
pause >nul

echo [7/7] All services started!
echo.
echo ========================================
echo Service URLs:
echo ========================================
if !HAS_PYTHON! equ 1 echo   AI Service:  http://localhost:5000
if !HAS_GO! equ 1     echo   Backend:     http://localhost:8080
if !HAS_NODE! equ 1   echo   Frontend:    http://localhost:3000
echo.
echo ========================================
echo Status:
echo ========================================
echo   - Check the opened windows for service status
echo   - Frontend will open automatically in browser
echo   - Default login: admin / admin123
echo.
echo   Press any key to exit...
pause >nul

echo URLs:
if !HAS_PYTHON! equ 1 echo   AI:       http://localhost:5000
if !HAS_GO! equ 1     echo   Backend:  http://localhost:8080
if !HAS_NODE! equ 1   echo   Frontend: http://localhost:3000
echo.
pause
