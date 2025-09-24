#!/bin/bash
# Launch script for Web Domain Scanner with Streamlit UI
# This script starts both the Flask API server and Streamlit UI

echo "🔍 Web Domain Scanner - Full Stack Launcher"
echo "==========================================="

# Check if Python is available
if ! command -v python &> /dev/null; then
    echo "❌ Python is not installed or not in PATH"
    exit 1
fi

# Check if required packages are installed
echo "📦 Checking dependencies..."

# Check Flask dependencies
python -c "import flask, flask_cors" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "⚠️  Flask dependencies missing. Installing..."
    pip install flask flask-cors
fi

# Check Streamlit dependencies
python -c "import streamlit, plotly, pandas" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "⚠️  Streamlit dependencies missing. Installing..."
    pip install -r streamlit_requirements.txt
fi

echo "✅ Dependencies checked"

# Function to cleanup on exit
cleanup() {
    echo "🛑 Shutting down servers..."
    kill $FLASK_PID 2>/dev/null
    kill $STREAMLIT_PID 2>/dev/null
    exit 0
}

# Set trap for cleanup
trap cleanup SIGINT SIGTERM

# Start Flask API server in background
echo "🚀 Starting Flask API server (port 5000)..."
cd src
python main.py &
FLASK_PID=$!

# Wait a moment for Flask to start
sleep 3

# Check if Flask is running
if ! curl -s http://localhost:5000/api/health > /dev/null; then
    echo "❌ Flask server failed to start"
    kill $FLASK_PID 2>/dev/null
    exit 1
fi

echo "✅ Flask API server is running"

# Start Streamlit UI
echo "🎨 Starting Streamlit UI (port 8501)..."
streamlit run streamlit_ui.py --server.port 8501 --server.address 0.0.0.0 &
STREAMLIT_PID=$!

# Wait a moment for Streamlit to start
sleep 5

echo ""
echo "🎉 Both servers are now running!"
echo "================================"
echo "📱 Streamlit UI: http://localhost:8501"
echo "🔧 Flask API:   http://localhost:5000"
echo ""
echo "Press Ctrl+C to stop both servers"

# Wait for user interrupt
wait