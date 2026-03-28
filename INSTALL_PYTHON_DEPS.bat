@echo off
setlocal enabledelayedexpansion

echo ========================================
echo Zein Security WAF - Install Python Dependencies
echo ========================================
echo.

REM Get script directory
cd /d "%~dp0"

echo [1/3] Checking Python installation...
set PYTHON_CMD=

where py >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON_CMD=py
    echo   [OK] Python found: py
) else (
    where python >nul 2>&1
    if %errorlevel% equ 0 (
        set PYTHON_CMD=python
        echo   [OK] Python found: python
    ) else (
        where python3 >nul 2>&1
        if %errorlevel% equ 0 (
            set PYTHON_CMD=python3
            echo   [OK] Python found: python3
        ) else (
            echo   [ERROR] Python not found!
            echo.
            echo   Please install Python 3.8+ from:
            echo   - https://www.python.org/downloads/
            echo   - Or use: winget install Python.Python.3.11
            echo.
            pause
            exit /b 1
        )
    )
)
echo.

echo [2/3] Upgrading pip...
cd backend\ai-service
%PYTHON_CMD% -m pip install --upgrade pip
if errorlevel 1 (
    echo   [WARN] Failed to upgrade pip, continuing anyway...
)
echo.

echo [3/3] Installing Python dependencies...
echo   This may take a few minutes...
echo.
%PYTHON_CMD% -m pip install fastapi "uvicorn[standard]" pydantic numpy scikit-learn python-multipart
if errorlevel 1 (
    echo.
    echo   [ERROR] Failed to install dependencies!
    echo   [INFO] Trying with requirements.txt...
    if exist requirements.txt (
        %PYTHON_CMD% -m pip install -r requirements.txt
        if errorlevel 1 (
            echo   [ERROR] Installation failed!
            echo   [INFO] Please check your Python installation and internet connection.
            pause
            exit /b 1
        )
    ) else (
        echo   [ERROR] requirements.txt not found!
        pause
        exit /b 1
    )
) else (
    echo.
    echo   [OK] All Python dependencies installed successfully!
)
cd ..\..

echo.
echo ========================================
echo Installation Complete!
echo ========================================
echo.
echo You can now run START.bat to start all services.
echo.
pause




