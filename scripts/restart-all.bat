@echo off
echo ========================================
echo Restart All Services
echo ========================================
echo.

echo [1/3] Stopping all Node processes...
taskkill /F /IM node.exe 2>nul
timeout /t 2 /nobreak >nul

echo.
echo [2/3] Fixing database password...
docker exec zein-postgres psql -U zein_waf -d zein_security -c "ALTER USER zein_waf WITH PASSWORD 'popyalena07';" 2>nul

echo.
echo [3/3] Starting all services...
echo.
echo Please run: npm run dev
echo.
pause




