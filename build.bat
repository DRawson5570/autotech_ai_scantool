@echo off
REM ============================================
REM  Build ELM327 Gateway App for Windows
REM ============================================

echo.
echo ========================================
echo  ELM327 Gateway - Build Script
echo ========================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found!
    echo Install Python 3.10+ from https://python.org
    pause
    exit /b 1
)

REM Install dependencies
echo [1/3] Installing dependencies...
python -m pip install -r requirements.txt pyinstaller
if errorlevel 1 (
    echo ERROR: Failed to install dependencies.
    pause
    exit /b 1
)

REM Verify imports work
echo [2/3] Verifying imports...
python -c "from elm327_gateway.app import main; print('OK')"
if errorlevel 1 (
    echo ERROR: Import verification failed.
    pause
    exit /b 1
)

REM Build single-file exe
echo [3/3] Building executable...
python -m PyInstaller gateway_app.spec --noconfirm
if errorlevel 1 (
    echo.
    echo BUILD FAILED. Check errors above.
    pause
    exit /b 1
)

echo.
echo ========================================
echo  BUILD SUCCESSFUL!
echo ========================================
echo.
echo  Output: dist\ELM327_Gateway.exe
echo.
echo  Just send that single file to anyone!
echo.
pause
