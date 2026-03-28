@echo off
echo ========================================
echo Zein Security WAF - Fix Python Dependencies
echo ========================================
echo.

cd backend\ai-service

echo [1/2] Upgrading pip...
py -m pip install --upgrade pip setuptools wheel

echo.
echo [2/2] Installing Python dependencies...
py -m pip install fastapi uvicorn[standard] pydantic numpy scikit-learn python-multipart

echo.
echo ========================================
echo Python dependencies installed!
echo ========================================
echo.

cd ..\..





