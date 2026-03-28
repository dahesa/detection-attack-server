@echo off
echo ========================================
echo Zein Security WAF - Complete Reset
echo ========================================
echo.
echo This will:
echo 1. Stop all Docker containers
echo 2. Remove all containers and volumes
echo 3. Remove all images (optional)
echo 4. Restart with fresh database
echo.
pause

echo.
echo [1/4] Stopping all containers...
docker-compose down

echo.
echo [2/4] Removing all volumes (this will delete all data)...
docker-compose down -v

echo.
echo [3/4] Removing unused images...
docker image prune -f

echo.
echo [4/4] Starting fresh database with password: popyalena07...
docker-compose up -d postgres redis

echo.
echo Waiting for database to be ready...
timeout /t 10 /nobreak >nul

echo.
echo ========================================
echo Reset complete!
echo ========================================
echo.
echo Database password: popyalena07
echo Database user: zein_waf
echo Database name: zein_security
echo.
echo You can now run: npm run dev
echo.
pause




