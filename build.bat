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
    echo.
    echo Install Python 3.10+ from https://python.org
    echo Make sure to check "Add Python to PATH" during install.
    echo.
    pause
    exit /b 1
)

REM Install dependencies
echo [1/3] Installing dependencies...
pip install -r requirements.txt pyinstaller
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

REM Build
echo [3/3] Building executable...
pyinstaller gateway_app.spec --noconfirm
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
echo  Output: dist\ELM327_Gateway\ELM327_Gateway.exe
echo.
echo  To run:
echo    dist\ELM327_Gateway\ELM327_Gateway.exe
echo.
echo  To run headless (no tray icon):
echo    dist\ELM327_Gateway\ELM327_Gateway.exe --headless
echo.
pause
