"""
Test AI Chat to Real-Time VAPT Workflow
User asks AI for VAPT, AI analyzes and executes Docker tools
"""
import requests
import json
import time

BASE_URL = "http://localhost:8000"

def test_ai_vapt_workflow():
    print("\n" + "="*100)
    print("🧪 TESTING AI CHAT → REAL-TIME VAPT WORKFLOW")
    print("="*100)
    
    # Step 1: Register user
    print("\n📝 Step 1: Registering user...")
    register_data = {
        "username": "vaptuser",
        "email": "vaptuser@test.com",
        "password": "VaptTest123!"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/api/auth/register", json=register_data)
        if response.status_code == 200:
            print("   ✅ User registered successfully")
        else:
            print(f"   ⚠️ Registration response: {response.status_code}")
    except Exception as e:
        print(f"   ⚠️ Registration error (user may exist): {e}")
    
    # Step 2: Login
    print("\n🔐 Step 2: Logging in...")
    login_data = {
        "username": "vaptuser",
        "password": "VaptTest123!"
    }
    
    response = requests.post(f"{BASE_URL}/api/auth/login", json=login_data)
    if response.status_code != 200:
        print(f"   ❌ Login failed: {response.text}")
        return
    
    token = response.json()["access_token"]
    print(f"   ✅ Login successful, token: {token[:30]}...")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Step 3: Send AI VAPT request
    print("\n💬 Step 3: Sending AI VAPT request...")
    print("   📤 Message: 'please do me a basic VAPT for this url https://demo.owasp-juice.shop/#/'")
    
    chat_data = {
        "message": "please do me a basic VAPT for this url https://demo.owasp-juice.shop/#/"
    }
    
    print("\n   ⏳ Processing (AI analyzing → tool selection → Docker execution)...")
    start_time = time.time()
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/chat/message",
            json=chat_data,
            headers=headers,
            timeout=120
        )
        
        elapsed = time.time() - start_time
        print(f"   ✅ Response received in {elapsed:.2f} seconds")
        
        if response.status_code != 200:
            print(f"   ❌ Error: {response.status_code} - {response.text}")
            return
        
        result = response.json()
        
        # Display full JSON for debugging
        print("\n🔍 DEBUG - Full Response JSON:")
        print(json.dumps(result, indent=2)[:500])
        print()
        
        # Display results
        print("\n" + "="*100)
        print("📊 AI RESPONSE:")
        print("="*100)
        response_text = result.get("response", result.get("message", ""))
        print(response_text[:1200] if len(response_text) > 1200 else response_text)
        if len(response_text) > 1200:
            print(f"\n... (truncated, total length: {len(response_text)} chars)")
        print("="*100)
        
        # Check if tools were executed
        tools_executed = result.get("tools_executed", [])
        target = result.get("target", "")
        scan_results = result.get("scan_results", {})
        
        if tools_executed:
            print("\n✅ REAL-TIME VAPT EXECUTED!")
            print(f"\n🔧 Tools Used:")
            for tool in tools_executed:
                print(f"   • {tool}")
            
            print(f"\n🎯 Target: {target}")
            
            if scan_results:
                print("\n🔍 Scan Results Summary:")
                print(json.dumps(scan_results, indent=2)[:800])
                if len(json.dumps(scan_results)) > 800:
                    print("   ... (results truncated)")
            
            print("\n✅ SUCCESS: AI analyzed request, selected tools, and executed real-time scans!")
            
        else:
            print("\n⚠️ No tools were executed")
            print("   Reason: AI provided consultation instead of executing scans")
            print("   This could be due to:")
            print("   - Docker socket not mounted in container")
            print("   - Intent not recognized as scan request")
            print("   - Tools not available")
        
        print("\n" + "="*100)
        print("🏁 TEST COMPLETE")
        print("="*100)
        
    except requests.exceptions.Timeout:
        print("   ❌ Request timeout (120s)")
    except Exception as e:
        print(f"   ❌ Error: {e}")

if __name__ == "__main__":
    test_ai_vapt_workflow()
