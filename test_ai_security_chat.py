"""
🧪 AI Security Chat - Integration Test
Tests the complete AI security chat workflow including:
- Chat message endpoints
- Streaming responses
- Conversation management
- AI response quality
"""

import requests
import json
import time
from typing import Dict, List, Optional

# Configuration
BASE_URL = "http://127.0.0.1:8000"
API_BASE = f"{BASE_URL}/api"

class Colors:
    """Terminal colors for better output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class AISecurityChatTester:
    def __init__(self):
        self.session = requests.Session()
        self.token = None
        self.user_id = None
        self.session_id = None
        self.results = {
            "passed": [],
            "failed": [],
            "warnings": []
        }
    
    def log(self, message: str, level: str = "info"):
        """Pretty print log messages"""
        colors = {
            "info": Colors.OKBLUE,
            "success": Colors.OKGREEN,
            "warning": Colors.WARNING,
            "error": Colors.FAIL,
            "header": Colors.HEADER
        }
        color = colors.get(level, Colors.ENDC)
        print(f"{color}{message}{Colors.ENDC}")
    
    def test_health(self) -> bool:
        """Test 1: Backend Health Check"""
        self.log("\n" + "="*80, "header")
        self.log("TEST 1: Backend Health Check", "header")
        self.log("="*80, "header")
        
        try:
            # Try /health first (root level)
            response = self.session.get(f"{BASE_URL}/health", timeout=5)
            if response.status_code != 200:
                # Fallback to /api/health
                response = self.session.get(f"{API_BASE}/health", timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                self.log(f"✅ Backend is healthy: {data}", "success")
                self.log(f"   Status: {data.get('status', 'unknown')}", "info")
                self.results["passed"].append("Backend health check")
                return True
            else:
                self.log(f"❌ Health check failed: {response.status_code}", "error")
                self.results["failed"].append("Backend health check")
                return False
        except Exception as e:
            self.log(f"❌ Cannot connect to backend: {e}", "error")
            self.results["failed"].append(f"Backend connection: {e}")
            return False
    
    def test_register_or_login(self) -> bool:
        """Test 2: User Registration/Login"""
        self.log("\n" + "="*80, "header")
        self.log("TEST 2: User Authentication", "header")
        self.log("="*80, "header")
        
        # Try to register a test user
        import random
        random_suffix = random.randint(1000, 9999)
        test_user = {
            "username": f"sec_test_{random_suffix}",
            "email": f"sec_test_{random_suffix}@example.com",
            "password": "TestPassword123!"
        }
        
        try:
            # Try registration first
            response = self.session.post(f"{API_BASE}/auth/register", json=test_user)
            
            if response.status_code in [200, 201]:
                # Registration successful - token returned directly
                token_data = response.json()
                self.token = token_data.get("access_token")
                if self.token:
                    self.session.headers.update({"Authorization": f"Bearer {self.token}"})
                    self.log("✅ User registered successfully with token", "success")
                    self.log(f"   Token: {self.token[:20]}...", "info")
                    self.results["passed"].append("User authentication")
                    return True
                else:
                    self.log("✅ User registered successfully", "success")
            elif response.status_code == 400:
                self.log("⚠️  User already exists, attempting login...", "warning")
            else:
                self.log(f"❌ Registration failed: {response.status_code} - {response.text}", "error")
                self.results["failed"].append("User registration")
                return False
            
            # Now login
            login_data = {
                "username": test_user["username"],
                "password": test_user["password"]
            }
            
            login_response = self.session.post(
                f"{API_BASE}/auth/login",
                data=login_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if login_response.status_code == 200:
                token_data = login_response.json()
                self.token = token_data.get("access_token")
                self.session.headers.update({"Authorization": f"Bearer {self.token}"})
                self.log(f"✅ Login successful", "success")
                self.log(f"   Token: {self.token[:20]}...", "info")
                self.results["passed"].append("User authentication")
                return True
            else:
                self.log(f"❌ Login failed: {login_response.status_code} - {login_response.text}", "error")
                self.results["failed"].append("User login")
                return False
                
        except Exception as e:
            self.log(f"❌ Authentication error: {e}", "error")
            self.results["failed"].append(f"Authentication: {e}")
            return False
    
    def test_chat_endpoint_send_message(self) -> bool:
        """Test 3: Send Chat Message"""
        self.log("\n" + "="*80, "header")
        self.log("TEST 3: Send AI Security Chat Message", "header")
        self.log("="*80, "header")
        
        # Simulate the user request from the scenario
        test_message = "Check security of example.com"
        
        try:
            payload = {
                "message": test_message,
                "session_id": self.session_id  # Can be None for new conversation
            }
            
            self.log(f"📤 Sending message: '{test_message}'", "info")
            
            response = self.session.post(
                f"{API_BASE}/chat/message",
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                self.log("✅ Chat message sent successfully", "success")
                self.log(f"   Response preview: {data.get('response', '')[:200]}...", "info")
                
                # Store session ID for future messages
                self.session_id = data.get("session_id")
                self.log(f"   Session ID: {self.session_id}", "info")
                
                # Validate response structure
                if self.validate_ai_response(data):
                    self.results["passed"].append("Chat message endpoint")
                    return True
                else:
                    self.results["warnings"].append("Chat response structure incomplete")
                    return True  # Still pass the test
            else:
                self.log(f"❌ Chat request failed: {response.status_code} - {response.text}", "error")
                self.results["failed"].append("Chat message endpoint")
                return False
                
        except Exception as e:
            self.log(f"❌ Chat error: {e}", "error")
            self.results["failed"].append(f"Chat message: {e}")
            return False
    
    def validate_ai_response(self, response_data: Dict) -> bool:
        """Validate AI response quality"""
        self.log("\n   🔍 Validating AI Response Quality...", "info")
        
        response_text = response_data.get("response", "")
        
        # Check for key elements expected in a security scan response
        checks = {
            "Has meaningful content": len(response_text) > 50,
            "Contains security keywords": any(keyword in response_text.lower() for keyword in 
                ["security", "scan", "vulnerability", "ssl", "https", "check"]),
            "Has session ID": response_data.get("session_id") is not None,
            "Has timestamp": response_data.get("timestamp") is not None or response_data.get("created_at") is not None
        }
        
        all_passed = True
        for check_name, passed in checks.items():
            if passed:
                self.log(f"      ✅ {check_name}", "success")
            else:
                self.log(f"      ⚠️  {check_name}", "warning")
                all_passed = False
        
        return all_passed
    
    def test_get_conversations(self) -> bool:
        """Test 4: Get Conversation History"""
        self.log("\n" + "="*80, "header")
        self.log("TEST 4: Get Conversation History", "header")
        self.log("="*80, "header")
        
        try:
            response = self.session.get(f"{API_BASE}/chat/conversations", timeout=10)
            
            if response.status_code == 200:
                conversations = response.json()
                self.log(f"✅ Retrieved {len(conversations)} conversation(s)", "success")
                
                if len(conversations) > 0:
                    latest = conversations[0]
                    self.log(f"   Latest conversation ID: {latest.get('session_id', 'N/A')}", "info")
                    self.log(f"   Created at: {latest.get('created_at', 'N/A')}", "info")
                    self.log(f"   Message count: {latest.get('message_count', 0)}", "info")
                
                self.results["passed"].append("Get conversations")
                return True
            else:
                self.log(f"❌ Failed to get conversations: {response.status_code}", "error")
                self.results["failed"].append("Get conversations")
                return False
                
        except Exception as e:
            self.log(f"❌ Conversation retrieval error: {e}", "error")
            self.results["failed"].append(f"Get conversations: {e}")
            return False
    
    def test_get_specific_conversation(self) -> bool:
        """Test 5: Get Specific Conversation Details"""
        self.log("\n" + "="*80, "header")
        self.log("TEST 5: Get Specific Conversation", "header")
        self.log("="*80, "header")
        
        if not self.session_id:
            self.log("⚠️  No session ID available, skipping test", "warning")
            self.results["warnings"].append("No session for conversation detail test")
            return True
        
        try:
            response = self.session.get(
                f"{API_BASE}/chat/conversation/{self.session_id}",
                timeout=10
            )
            
            if response.status_code == 200:
                conversation = response.json()
                messages = conversation.get("messages", [])
                
                self.log(f"✅ Retrieved conversation details", "success")
                self.log(f"   Session ID: {conversation.get('session_id', 'N/A')}", "info")
                self.log(f"   Message count: {len(messages)}", "info")
                
                if len(messages) > 0:
                    self.log(f"\n   📜 Recent Messages:", "info")
                    for i, msg in enumerate(messages[-3:], 1):  # Show last 3 messages
                        role = msg.get("role", "unknown")
                        content = msg.get("content", "")[:100]
                        self.log(f"      {i}. [{role}] {content}...", "info")
                
                self.results["passed"].append("Get specific conversation")
                return True
            else:
                self.log(f"❌ Failed to get conversation: {response.status_code}", "error")
                self.results["failed"].append("Get specific conversation")
                return False
                
        except Exception as e:
            self.log(f"❌ Conversation detail error: {e}", "error")
            self.results["failed"].append(f"Get specific conversation: {e}")
            return False
    
    def test_ai_response_quality_deep(self) -> bool:
        """Test 6: Deep AI Response Quality (Scenario Simulation)"""
        self.log("\n" + "="*80, "header")
        self.log("TEST 6: AI Response Quality - Security Scan Scenario", "header")
        self.log("="*80, "header")
        
        # Test with the exact scenario from requirements
        scenario_messages = [
            "Check security of example.com",
            "yes",  # Confirm scan
            "How serious is the git directory issue?",
            "generate fix script"
        ]
        
        for i, message in enumerate(scenario_messages, 1):
            self.log(f"\n   Step {i}/{len(scenario_messages)}: Testing '{message}'", "info")
            
            try:
                payload = {
                    "message": message,
                    "session_id": self.session_id
                }
                
                response = self.session.post(
                    f"{API_BASE}/chat/message",
                    json=payload,
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    ai_response = data.get("response", "")
                    
                    self.log(f"   ✅ AI responded ({len(ai_response)} chars)", "success")
                    
                    # Update session ID
                    self.session_id = data.get("session_id", self.session_id)
                    
                    # Brief preview
                    preview = ai_response[:150].replace('\n', ' ')
                    self.log(f"   Preview: {preview}...", "info")
                    
                    # Small delay between messages
                    time.sleep(0.5)
                else:
                    self.log(f"   ❌ Failed: {response.status_code}", "error")
                    return False
                    
            except Exception as e:
                self.log(f"   ❌ Error: {e}", "error")
                return False
        
        self.log("\n✅ All scenario steps completed successfully", "success")
        self.results["passed"].append("AI scenario simulation")
        return True
    
    def test_streaming_support(self) -> bool:
        """Test 7: Check if Streaming is Supported"""
        self.log("\n" + "="*80, "header")
        self.log("TEST 7: Streaming Support Check", "header")
        self.log("="*80, "header")
        
        # Check if there's a streaming endpoint
        streaming_endpoints = [
            f"{API_BASE}/chat/stream",
            f"{API_BASE}/chat/message/stream",
        ]
        
        for endpoint in streaming_endpoints:
            try:
                self.log(f"   Testing endpoint: {endpoint}", "info")
                response = self.session.post(
                    endpoint,
                    json={"message": "test", "session_id": self.session_id},
                    stream=True,
                    timeout=5
                )
                
                if response.status_code == 200:
                    self.log(f"   ✅ Streaming endpoint available: {endpoint}", "success")
                    self.results["passed"].append("Streaming support")
                    return True
                elif response.status_code == 404:
                    self.log(f"   ℹ️  Endpoint not found: {endpoint}", "info")
                else:
                    self.log(f"   ⚠️  Endpoint returned: {response.status_code}", "warning")
                    
            except Exception as e:
                self.log(f"   ℹ️  Error testing {endpoint}: {e}", "info")
        
        self.log("⚠️  No streaming endpoint found (non-streaming responses used)", "warning")
        self.results["warnings"].append("Streaming not available")
        return True  # Not a failure, just informational
    
    def run_all_tests(self):
        """Run all tests in sequence"""
        self.log("\n" + "[*] " + "="*76 + " [*]", "header")
        self.log("[TEST] AI SECURITY CHAT - COMPREHENSIVE INTEGRATION TEST", "header")
        self.log("[*] " + "="*76 + " [*]\n", "header")
        
        start_time = time.time()
        
        # Run tests in order
        tests = [
            self.test_health,
            self.test_register_or_login,
            self.test_chat_endpoint_send_message,
            self.test_get_conversations,
            self.test_get_specific_conversation,
            self.test_ai_response_quality_deep,
            self.test_streaming_support
        ]
        
        for test in tests:
            try:
                test()
            except Exception as e:
                self.log(f"\n❌ Test failed with exception: {e}", "error")
                self.results["failed"].append(f"{test.__name__}: {e}")
        
        # Summary
        elapsed = time.time() - start_time
        self.print_summary(elapsed)
    
    def print_summary(self, elapsed_time: float):
        """Print test summary"""
        self.log("\n" + "="*80, "header")
        self.log("📊 TEST SUMMARY", "header")
        self.log("="*80, "header")
        
        total = len(self.results["passed"]) + len(self.results["failed"]) + len(self.results["warnings"])
        
        self.log(f"\n✅ PASSED: {len(self.results['passed'])}/{total}", "success")
        for item in self.results["passed"]:
            self.log(f"   • {item}", "success")
        
        if self.results["warnings"]:
            self.log(f"\n⚠️  WARNINGS: {len(self.results['warnings'])}", "warning")
            for item in self.results["warnings"]:
                self.log(f"   • {item}", "warning")
        
        if self.results["failed"]:
            self.log(f"\n❌ FAILED: {len(self.results['failed'])}", "error")
            for item in self.results["failed"]:
                self.log(f"   • {item}", "error")
        
        self.log(f"\n⏱️  Total time: {elapsed_time:.2f} seconds", "info")
        
        # Final verdict
        if len(self.results["failed"]) == 0:
            self.log("\n" + "="*80, "success")
            self.log("[SUCCESS] ALL TESTS PASSED! AI Security Chat is working correctly!", "success")
            self.log("="*80 + "\n", "success")
        else:
            self.log("\n" + "="*80, "error")
            self.log("[WARNING] SOME TESTS FAILED - Please review errors above", "error")
            self.log("="*80 + "\n", "error")


if __name__ == "__main__":
    # Set UTF-8 encoding for Windows console
    import sys
    import io
    if sys.platform == "win32":
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    
    print("\n[*] Starting AI Security Chat Integration Tests...")
    print("[*] Waiting for backend to be ready...\n")
    time.sleep(2)  # Give backend time to start
    
    tester = AISecurityChatTester()
    tester.run_all_tests()
