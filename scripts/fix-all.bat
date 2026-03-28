@echo off
echo ========================================
echo Fix All Issues - Database & Frontend
echo ========================================
echo.

echo [1/5] Stopping all Node processes...
taskkill /F /IM node.exe 2>nul
timeout /t 2 /nobreak >nul

echo.
echo [2/5] Fixing database password...
docker exec zein-postgres psql -U zein_waf -d zein_security -c "ALTER USER zein_waf WITH PASSWORD 'popyalena07';" 2>nul
if errorlevel 1 (
    echo Database container not running. Starting...
    docker-compose up -d postgres redis
    timeout /t 15 /nobreak >nul
    docker exec zein-postgres psql -U zein_waf -d zein_security -c "ALTER USER zein_waf WITH PASSWORD 'popyalena07';"
)

echo.
echo [3/5] Testing database connection...
docker exec zein-postgres psql -U zein_waf -d zein_security -c "SELECT 'OK' as status;" 2>nul
if errorlevel 1 (
    echo ERROR: Database connection failed!
    echo Please check Docker is running and database container is up.
    pause
    exit /b 1
)

echo.
echo [4/5] Clearing Vite cache...
cd frontend
if exist "node_modules\.vite" (
    rmdir /s /q "node_modules\.vite" 2>nul
)
cd ..

echo.
echo [5/5] Ready to start!
echo.
echo ========================================
echo All fixes applied!
echo ========================================
echo.
echo Now run: npm run dev
echo.
echo Frontend will be available at: http://localhost:3000
echo.
pause




