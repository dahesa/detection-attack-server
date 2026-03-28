@echo off
echo ========================================
echo Fix Database Password
echo ========================================
echo.

echo Setting database password to: popyalena07
docker exec zein-postgres psql -U zein_waf -d zein_security -c "ALTER USER zein_waf WITH PASSWORD 'popyalena07';"

echo.
echo Testing connection...
docker exec zein-postgres psql -U zein_waf -d zein_security -c "SELECT 'Connection OK' as status;"

echo.
echo ========================================
echo Password updated!
echo ========================================
echo.
echo Now restart the backend service.
echo.
pause




