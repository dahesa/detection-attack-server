@echo off
echo ========================================
echo Zein Security WAF - Database Reset
echo ========================================
echo.
echo This will stop and remove the PostgreSQL container and its data.
echo.
pause

echo.
echo [1/3] Stopping Docker containers...
docker-compose down

echo.
echo [2/3] Removing PostgreSQL volume...
docker volume rm zeinsec-v2_postgres_data 2>nul
if errorlevel 1 (
    echo Volume not found or already removed.
)

echo.
echo [3/3] Starting fresh database...
docker-compose up -d postgres redis

echo.
echo Waiting for database to be ready...
timeout /t 10 /nobreak >nul

echo.
echo ========================================
echo Database reset complete!
echo ========================================
echo.
echo The database has been reset with default password: popyalena07
echo You can now start the application with: npm run dev
echo.

