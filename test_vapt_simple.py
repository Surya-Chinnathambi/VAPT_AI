"""
Simple VAPT test to debug issues
"""
import requests
import time

BASE_URL = "http://localhost:8000"

# Step 1: Login
print("Authenticating...")
response = requests.post(f"{BASE_URL}/api/auth/login", json={
    "username": "scantest2",
    "password": "Test123!"
})
token = response.json()["access_token"]
print(f"✓ Authenticated")

# Step 2: Start VAPT scan
print("\nStarting VAPT scan...")
headers = {"Authorization": f"Bearer {token}"}
response = requests.post(f"{BASE_URL}/api/vapt/start", json={
    "target": "http://testphp.vulnweb.com",
    "phases": ["reconnaissance"],
    "deep_scan": False,
    "include_exploitation": False
}, headers=headers)

if response.status_code != 200:
    print(f"✗ Failed to start scan: {response.status_code}")
    print(response.text)
    exit(1)

data = response.json()
scan_id = data["scan_id"]
print(f"✓ Scan started: {scan_id}")

# Step 3: Wait and check status
print("\nWaiting for scan to process...")
for i in range(10):
    time.sleep(3)
    print(f"Checking status ({i+1}/10)...")
    
    # Try to get report
    response = requests.get(f"{BASE_URL}/api/vapt/report/{scan_id}", headers=headers)
    print(f"  Status code: {response.status_code}")
    
    if response.status_code == 200:
        print("✓ Scan completed!")
        report = response.json()
        print(f"  Risk Score: {report['executive_summary']['overall_risk_score']}")
        break
    elif response.status_code == 400:
        print(f"  {response.json()}")
    else:
        print(f"  Error: {response.text}")

print("\nTest complete")
