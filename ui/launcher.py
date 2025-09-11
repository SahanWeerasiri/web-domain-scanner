import streamlit as st
import subprocess
import sys
import os
import time
import requests

def check_server_status():
    """Check if the FastAPI server is running"""
    try:
        response = requests.get("http://localhost:8000", timeout=2)
        return True
    except:
        return False

def main():
    st.set_page_config(
        page_title="Scanner Launcher",
        page_icon="🚀",
        layout="wide"
    )
    
    st.title("🚀 Web Domain Scanner Launcher")
    
    # Check server status
    server_running = check_server_status()
    
    col1, col2 = st.columns(2)
    
    with col1:
        if server_running:
            st.success("✅ FastAPI Server is running!")
            st.info("Server URL: http://localhost:8000")
        else:
            st.error("❌ FastAPI Server is not running!")
            st.warning("Please start the server first by running:")
            st.code("cd src && python server.py")
    
    with col2:
        st.info("🌐 Streamlit UI Status")
        st.success("✅ UI is running!")
        st.info("UI URL: http://localhost:8501")
    
    st.markdown("---")
    
    if server_running:
        st.success("🎉 All services are ready!")
        if st.button("🔍 Open Scanner UI", type="primary"):
            # This will redirect to the main scanner app
            st.switch_page("streamlit_app.py")
    else:
        st.error("⚠️ Cannot start scanner - server is not running")
        st.markdown("""
        ### To start the server:
        
        **Option 1: Use the startup script**
        ```bash
        # On Windows
        start_scanner.bat
        
        # On Linux/Mac
        ./start_scanner.sh
        ```
        
        **Option 2: Manual startup**
        ```bash
        cd src
        python server.py
        ```
        """)

if __name__ == "__main__":
    main()
