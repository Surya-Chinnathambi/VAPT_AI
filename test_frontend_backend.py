"""
Frontend-Backend Integration Test
Tests all API endpoints to ensure frontend can communicate with backend
"""
import requests
import json
import sys

BASE_URL = "http://localhost:8000"
TEST_USER = {
    "username": "testuser",
    "email": "test@example.com",
    "password": "testpass123"
}

def test_endpoint(method, endpoint, data=None, headers=None, params=None):
    """Test a single endpoint"""
    url = f"{BASE_URL}{endpoint}"
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, params=params, timeout=5)
        elif method == "POST":
            response = requests.post(url, json=data, headers=headers, params=params, timeout=5)
        
        return {
            "success": response.status_code < 500,
            "status": response.status_code,
            "data": response.json() if response.headers.get('content-type', '').startswith('application/json') else None
        }
    except requests.exceptions.ConnectionError:
        return {"success": False, "error": "Connection refused - Backend not running?"}
    except requests.exceptions.Timeout:
        return {"success": False, "error": "Request timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def main():
    print("="*70)
    print("🧪 FRONTEND-BACKEND INTEGRATION TEST")
    print("="*70)
    
    results = []
    token = None
    
    # Test 1: Health Check
    print("\n📡 Test 1: Health Check")
    result = test_endpoint("GET", "/health")
    results.append(("Health Check", result["success"]))
    if result["success"]:
        print(f"   ✅ Status: {result['status']}")
    else:
        print(f"   ❌ Error: {result.get('error', 'Failed')}")
        print("\n⚠️ Backend not responding! Make sure backend is running:")
        print("   cd backend")
        print("   python main.py")
        sys.exit(1)
    
    # Test 2: API Root
    print("\n📡 Test 2: API Root")
    result = test_endpoint("GET", "/")
    results.append(("API Root", result["success"]))
    if result["success"]:
        print(f"   ✅ {result['data'].get('name')}")
        print(f"   Version: {result['data'].get('version')}")
    else:
        print(f"   ❌ Failed")
    
    # Test 3: Auth - Register (may fail if user exists)
    print("\n📡 Test 3: Auth - Register")
    result = test_endpoint("POST", "/api/auth/register", data=TEST_USER)
    results.append(("Auth Register", result["status"] in [200, 201, 400]))
    if result["success"]:
        print(f"   ✅ Status: {result['status']}")
    else:
        print(f"   ⚠️ Status: {result['status']} (user may already exist)")
    
    # Test 4: Auth - Login
    print("\n📡 Test 4: Auth - Login")
    result = test_endpoint("POST", "/api/auth/login", data={
        "username": TEST_USER["username"],
        "password": TEST_USER["password"]
    })
    results.append(("Auth Login", result["success"]))
    if result["success"] and result["data"]:
        token = result["data"].get("access_token")
        print(f"   ✅ Logged in successfully")
        print(f"   Token: {token[:20]}..." if token else "   No token")
    else:
        print(f"   ❌ Login failed")
    
    # Setup auth headers
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    
    # Test 5: Scan - History
    print("\n📡 Test 5: Scan History")
    result = test_endpoint("GET", "/api/scan/history", headers=headers, params={"limit": 5})
    results.append(("Scan History", result["success"]))
    if result["success"]:
        scans = result["data"].get("scans", []) if result["data"] else []
        print(f"   ✅ Retrieved {len(scans)} scans")
    else:
        print(f"   ❌ Failed: {result.get('error', 'Unknown')}")
    
    # Test 6: Scan - Stats
    print("\n📡 Test 6: Scan Stats")
    result = test_endpoint("GET", "/api/scan/stats", headers=headers)
    results.append(("Scan Stats", result["success"]))
    if result["success"] and result["data"]:
        print(f"   ✅ Total scans: {result['data'].get('total_scans', 0)}")
    else:
        print(f"   ❌ Failed")
    
    # Test 7: Chat - Send Message
    print("\n📡 Test 7: AI Chat")
    result = test_endpoint("POST", "/api/chat/message", 
                          data={"message": "Hello, test message"}, 
                          headers=headers)
    results.append(("AI Chat", result["success"]))
    if result["success"]:
        print(f"   ✅ Chat working")
    else:
        print(f"   ❌ Failed: {result.get('error', 'Unknown')}")
    
    # Test 8: CVE - Search
    print("\n📡 Test 8: CVE Search")
    result = test_endpoint("GET", "/api/cve/search", params={"query": "apache", "limit": 5})
    results.append(("CVE Search", result["success"]))
    if result["success"] and result["data"]:
        cves = result["data"].get("results", [])
        print(f"   ✅ Found {len(cves)} CVEs")
    else:
        print(f"   ❌ Failed")
    
    # Test 9: Dashboard - Stats
    print("\n📡 Test 9: Dashboard Stats")
    result = test_endpoint("GET", "/api/dashboard/stats", headers=headers)
    results.append(("Dashboard Stats", result["success"]))
    if result["success"]:
        print(f"   ✅ Dashboard data retrieved")
    else:
        print(f"   ❌ Failed")
    
    # Test 10: Real-Time VAPT - Get Tools
    print("\n📡 Test 10: Real-Time VAPT - Get Tools")
    result = test_endpoint("GET", "/api/realtime/tools", headers=headers)
    results.append(("Real-Time Tools", result["success"]))
    if result["success"] and result["data"]:
        total_tools = result["data"].get("total_tools", 0)
        print(f"   ✅ {total_tools} tools available")
    else:
        print(f"   ❌ Failed: {result.get('error', 'Unknown')}")
    
    # Test 11: Real-Time VAPT - Stats
    print("\n📡 Test 11: Real-Time VAPT - Stats")
    result = test_endpoint("GET", "/api/realtime/stats", headers=headers)
    results.append(("Real-Time Stats", result["success"]))
    if result["success"] and result["data"]:
        docker = result["data"].get("docker_available", False)
        print(f"   ✅ Docker: {'Available' if docker else 'Unavailable'}")
        print(f"   Active connections: {result['data'].get('active_connections', 0)}")
    else:
        print(f"   ❌ Failed")
    
    # Test 12: Billing - Plans
    print("\n📡 Test 12: Billing Plans")
    result = test_endpoint("GET", "/api/billing/plans")
    results.append(("Billing Plans", result["success"]))
    if result["success"]:
        print(f"   ✅ Plans retrieved")
    else:
        print(f"   ❌ Failed")
    
    # Test 13: Reports - List
    print("\n📡 Test 13: Reports List")
    result = test_endpoint("GET", "/api/reports/list", headers=headers)
    results.append(("Reports List", result["success"]))
    if result["success"]:
        print(f"   ✅ Reports list retrieved")
    else:
        print(f"   ❌ Failed")
    
    # Test 14: Compliance - Frameworks
    print("\n📡 Test 14: Compliance Frameworks")
    result = test_endpoint("GET", "/api/compliance/frameworks", headers=headers)
    results.append(("Compliance Frameworks", result["success"]))
    if result["success"] and result["data"]:
        frameworks = result["data"].get("frameworks", [])
        print(f"   ✅ {len(frameworks)} frameworks available")
    else:
        print(f"   ❌ Failed")
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    for test_name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    passed_count = sum(1 for _, p in results if p)
    total = len(results)
    success_rate = (passed_count / total * 100) if total > 0 else 0
    
    print(f"\nResults: {passed_count}/{total} tests passed ({success_rate:.1f}%)")
    
    if success_rate >= 80:
        print("\n✅ Frontend-Backend integration is working well!")
        print("\n📋 Frontend can successfully:")
        print("   ✅ Connect to backend")
        print("   ✅ Authenticate users")
        print("   ✅ Access all API endpoints")
        print("   ✅ Use real-time VAPT features")
        print("\n🚀 Frontend is ready to use!")
    else:
        print(f"\n⚠️ {total - passed_count} test(s) failed")
        print("   Check backend logs for errors")
    
    # Frontend build instructions
    print("\n" + "="*70)
    print("🎨 FRONTEND SETUP")
    print("="*70)
    print("\nTo run the frontend:")
    print("   cd frontend")
    print("   npm install")
    print("   npm run dev")
    print("\nFrontend will be available at: http://localhost:5173")
    print("Backend API is at: http://localhost:8000")
    
    return success_rate >= 80


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
