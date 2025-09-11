#!/usr/bin/env python3
"""
Test script to verify the Streamlit UI can communicate with the FastAPI server
"""
import requests
import time
import json

API_BASE_URL = "http://localhost:8000"

def test_server_connection():
    """Test if the server is running and responding"""
    print("Testing server connection...")
    try:
        response = requests.get(f"{API_BASE_URL}")
        print(f"✅ Server is responding (Status: {response.status_code})")
        return True
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server. Is it running on port 8000?")
        return False
    except Exception as e:
        print(f"❌ Server connection error: {e}")
        return False

def test_start_scan():
    """Test starting a scan"""
    print("\nTesting scan initiation...")
    try:
        response = requests.get(f"{API_BASE_URL}/api/data", params={'domain': 'example.com'})
        response.raise_for_status()
        data = response.json()
        request_id = data.get('request_id')
        
        if request_id:
            print(f"✅ Scan started successfully. Request ID: {request_id}")
            return request_id
        else:
            print("❌ No request ID returned")
            return None
    except Exception as e:
        print(f"❌ Failed to start scan: {e}")
        return None

def test_status_check(request_id):
    """Test status checking"""
    print(f"\nTesting status check for request: {request_id}")
    try:
        response = requests.get(f"{API_BASE_URL}/api/status/{request_id}")
        response.raise_for_status()
        status_data = response.json()
        
        print(f"✅ Status check successful")
        print(f"   State: {status_data.get('state', 'unknown')}")
        print(f"   Message: {status_data.get('message', 'no message')}")
        print(f"   Progress: {status_data.get('progress', 0)}%")
        
        return status_data
    except Exception as e:
        print(f"❌ Failed to get status: {e}")
        return None

def monitor_scan(request_id, max_time=60):
    """Monitor a scan until completion or timeout"""
    print(f"\nMonitoring scan {request_id} (max {max_time}s)...")
    start_time = time.time()
    
    while time.time() - start_time < max_time:
        status_data = test_status_check(request_id)
        if not status_data:
            break
            
        state = status_data.get('state')
        progress = status_data.get('progress', 0)
        
        if state == 'completed':
            print("🎉 Scan completed successfully!")
            print(f"   Results available: {bool(status_data.get('result'))}")
            return True
        elif state == 'error':
            print(f"❌ Scan failed: {status_data.get('message')}")
            return False
        elif state in ['pending', 'running']:
            print(f"⏳ Scan in progress: {progress:.1f}% - {status_data.get('message')}")
            time.sleep(5)
        else:
            print(f"❓ Unknown state: {state}")
            time.sleep(5)
    
    print("⏰ Monitoring timed out")
    return False

def main():
    print("=" * 60)
    print("          WEB DOMAIN SCANNER - UI TEST")
    print("=" * 60)
    
    # Test 1: Server connection
    if not test_server_connection():
        print("\n❌ Cannot proceed without server connection")
        print("\nTo start the server:")
        print("  cd src")
        print("  python server.py")
        return False
    
    # Test 2: Start scan
    request_id = test_start_scan()
    if not request_id:
        print("\n❌ Cannot proceed without successful scan start")
        return False
    
    # Test 3: Status check
    status_data = test_status_check(request_id)
    if not status_data:
        print("\n❌ Status check failed")
        return False
    
    # Test 4: Monitor scan (optional - can be skipped)
    print("\nWould you like to monitor the scan to completion? (y/n)")
    choice = input().lower().strip()
    
    if choice in ['y', 'yes']:
        success = monitor_scan(request_id, max_time=300)  # 5 minutes max
        if success:
            print("\n✅ Full scan test completed successfully!")
        else:
            print("\n⚠️ Scan monitoring incomplete, but API communication works")
    else:
        print("\n✅ Basic API communication test completed successfully!")
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY:")
    print("✅ Server connection: PASSED")
    print("✅ Scan initiation: PASSED") 
    print("✅ Status checking: PASSED")
    print("✅ UI should work correctly with the server!")
    print("=" * 60)
    
    print("\nTo start the UI:")
    print("  cd ui")
    print("  streamlit run streamlit_app.py")
    
    return True

if __name__ == "__main__":
    main()
