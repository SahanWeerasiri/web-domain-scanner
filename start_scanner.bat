@echo off
setlocal EnableDelayedExpansion

echo# Start Streamlit UI
echo [INFO] Starting Streamlit UI...
cd /d "%UI_DIR%"
start "Streamlit UI" cmd /k "streamlit run streamlit_app.py --server.port 8501 --server.address localhost"=======================================
echo     Web Domain Scanner - Startup
echo ==========================================

set PROJECT_DIR=%~dp0
set SERVER_DIR=%PROJECT_DIR%src
set UI_DIR=%PROJECT_DIR%ui

echo [INFO] Starting Web Domain Scanner...

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed. Please install Python 3.8 or higher.
    pause
    exit /b 1
)

echo [INFO] Python found: 
python --version

:: Install UI dependencies
echo [INFO] Installing UI dependencies...
cd /d "%UI_DIR%"
if exist requirements_ui.txt (
    pip install -r requirements_ui.txt
    echo [INFO] UI dependencies installed successfully!
) else (
    echo [WARNING] requirements_ui.txt not found. Installing basic dependencies...
    pip install streamlit requests pandas plotly
)

:: Install server dependencies
cd /d "%PROJECT_DIR%"
if exist requirements.txt (
    echo [INFO] Installing server dependencies...
    pip install -r requirements.txt
)

:: Start FastAPI server
echo [INFO] Starting FastAPI server...
cd /d "%SERVER_DIR%"
start "FastAPI Server" cmd /k "python server.py"

:: Wait a moment for server to start
timeout /t 3 /nobreak >nul

:: Start Streamlit UI
echo [INFO] Starting Streamlit UI...
cd /d "%UI_DIR%"
start "Streamlit UI" cmd /k "streamlit run streamlit_app.py --server.port 8501 --server.address 0.0.0.0"

echo.
echo ==========================================
echo     Services Started Successfully!
echo ==========================================
echo FastAPI Server: http://localhost:8000
echo Streamlit UI:   http://localhost:8501
echo ==========================================
echo.
echo Both services are running in separate windows.
echo Close this window or press any key to continue...
pause >nul
