@echo off
echo ========================================
echo Zein Security WAF - Database Reset
echo ========================================
echo.
echo This will completely reset the database with password: popyalena07
echo.
pause

echo.
echo [1/4] Stopping all containers...
docker-compose down

echo.
echo [2/4] Removing PostgreSQL volume (this will delete all data)...
docker volume rm zeinsec-v2_postgres_data 2>nul
if errorlevel 1 (
    docker volume ls | findstr postgres_data
    if errorlevel 1 (
        echo Volume not found, continuing...
    ) else (
        echo Removing volume...
        for /f "tokens=2" %%v in ('docker volume ls ^| findstr postgres_data') do docker volume rm %%v
    )
)

echo.
echo [3/4] Starting fresh database with password: popyalena07...
docker-compose up -d postgres redis

echo.
echo [4/4] Waiting for database to be ready...
timeout /t 15 /nobreak >nul

echo.
echo Testing database connection...
docker exec zein-postgres psql -U zein_waf -d zein_security -c "SELECT version();" 2>nul
if errorlevel 1 (
    echo Database is still initializing, please wait...
    timeout /t 10 /nobreak >nul
)

echo.
echo ========================================
echo Database reset complete!
echo ========================================
echo.
echo Database password: popyalena07
echo Database user: zein_waf
echo Database name: zein_security
echo.
echo You can now run: npm run dev
echo.
pause




