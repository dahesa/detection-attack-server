@echo off
echo Killing process on port 8080...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8080 ^| findstr LISTENING') do (
    echo Found PID: %%a
    taskkill /F /PID %%a
    if errorlevel 1 (
        echo Failed to kill process %%a. Try running as Administrator.
    ) else (
        echo Successfully killed process %%a
    )
)
echo Done.
pause



