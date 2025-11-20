"""Simple manual Nmap scan test"""
import requests
import time
import json

BASE_URL = "http://localhost:8000"

# Get token
print("1. Logging in...")
response = requests.post(f"{BASE_URL}/api/auth/login", json={
    "username": "scantest2",
    "password": "Test123!"
})

if response.status_code != 200:
    print(f"Login failed: {response.status_code} - {response.text}")
    exit(1)

token = response.json()['access_token']
print(f"✓ Logged in successfully")

headers = {"Authorization": f"Bearer {token}"}

# Test 1: Sync Nmap Scan
print("\n2. Testing SYNC Nmap scan...")
try:
    response = requests.post(
        f"{BASE_URL}/api/scan/nmap",
        headers=headers,
        json={"target": "testphp.vulnweb.com", "scan_type": "quick", "async_mode": False}
    )
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        result = response.json()
        print("✓ SYNC scan completed!")
        print(json.dumps(result, indent=2, default=str)[:500])
    else:
        print(f"✗ SYNC scan failed: {response.text}")
except Exception as e:
    print(f"✗ Error: {e}")

# Test 2: Async Nmap Scan
print("\n3. Testing ASYNC Nmap scan...")
try:
    response = requests.post(
        f"{BASE_URL}/api/scan/nmap",
        headers=headers,
        json={"target": "testphp.vulnweb.com", "scan_type": "quick", "async_mode": True}
    )
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        result = response.json()
        scan_id = result.get('scan_id')
        print(f"✓ ASYNC scan started: {scan_id}")
        
        # Poll for results
        for i in range(20):
            time.sleep(2)
            status_resp = requests.get(f"{BASE_URL}/api/scan/status/{scan_id}", headers=headers)
            if status_resp.status_code == 200:
                data = status_resp.json()
                status = data.get('status')
                print(f"  Poll {i+1}: {status}")
                
                if status == 'completed':
                    print("✓ ASYNC scan completed!")
                    print(json.dumps(data, indent=2, default=str)[:500])
                    break
                elif status == 'failed':
                    print(f"✗ ASYNC scan failed: {data.get('error', 'Unknown error')}")
                    break
            else:
                print(f"  Poll {i+1}: Status check failed - {status_resp.status_code}")
    else:
        print(f"✗ ASYNC scan failed to start: {response.text}")
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()

print("\n✓ Test complete")
