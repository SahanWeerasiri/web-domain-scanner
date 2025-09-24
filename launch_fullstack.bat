@echo off
REM Launch script for Web Domain Scanner with Streamlit UI (Windows)
REM This script starts both the Flask API server and Streamlit UI

echo 🔍 Web Domain Scanner - Full Stack Launcher
echo ===========================================

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed or not in PATH
    pause
    exit /b 1
)

REM Check if required packages are installed
echo 📦 Checking dependencies...

REM Check Flask dependencies
python -c "import flask, flask_cors" 2>nul
if errorlevel 1 (
    echo ⚠️  Flask dependencies missing. Installing...
    pip install flask flask-cors
)

REM Check Streamlit dependencies
python -c "import streamlit, plotly, pandas" 2>nul
if errorlevel 1 (
    echo ⚠️  Streamlit dependencies missing. Installing...
    pip install -r streamlit_requirements.txt
)

echo ✅ Dependencies checked

REM Start Flask API server in background
echo 🚀 Starting Flask API server (port 5000)...
cd src
start /B python main.py

REM Wait a moment for Flask to start
timeout /t 3 /nobreak >nul

REM Check if Flask is running
curl -s http://localhost:5000/api/health >nul 2>&1
if errorlevel 1 (
    echo ❌ Flask server failed to start or curl not available
    echo    Please ensure the Flask server starts manually first
)

echo ✅ Flask API server should be running

REM Start Streamlit UI
echo 🎨 Starting Streamlit UI (port 8501)...
streamlit run streamlit_ui.py --server.port 8501 --server.address 0.0.0.0

echo.
echo 🎉 Streamlit UI is now running!
echo ================================
echo 📱 Streamlit UI: http://localhost:8501
echo 🔧 Flask API:   http://localhost:5000
echo.
echo Press Ctrl+C to stop servers

pause