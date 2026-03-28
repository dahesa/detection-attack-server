@echo off
echo ========================================
echo Test Database Connection
echo ========================================
echo.

echo Testing connection with password: popyalena07
echo.

docker exec zein-postgres psql -U zein_waf -d zein_security -c "SELECT current_user, current_database(), version();"

echo.
echo ========================================
echo Connection test complete!
echo ========================================
pause




