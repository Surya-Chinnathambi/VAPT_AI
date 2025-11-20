"""
Load testing for concurrent users - Backend API
Tests system behavior with 2-3 simultaneous users performing various operations
"""

import pytest
import asyncio
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from fastapi.testclient import TestClient
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main import app
from models.user import User
from utils.database import get_db, engine
from sqlalchemy.orm import Session
import random
import string

# Test client
client = TestClient(app)


class TestConcurrentUsers:
    """Test suite for concurrent user load testing"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test environment"""
        # Create test users
        self.test_users = []
        for i in range(3):
            username = f"loadtest_user_{i}_{int(time.time())}"
            email = f"loadtest{i}@example.com"
            password = "TestPass123!@#"
            
            self.test_users.append({
                "username": username,
                "email": email,
                "password": password,
                "token": None
            })
        
        # Register and login users
        for user_data in self.test_users:
            # Register
            response = client.post("/api/auth/register", json={
                "username": user_data["username"],
                "email": user_data["email"],
                "password": user_data["password"]
            })
            
            # Login to get token
            response = client.post("/api/auth/login", data={
                "username": user_data["username"],
                "password": user_data["password"]
            })
            if response.status_code == 200:
                user_data["token"] = response.json().get("access_token")
        
        yield
        
        # Cleanup
        db = next(get_db())
        try:
            for user_data in self.test_users:
                user = db.query(User).filter(User.username == user_data["username"]).first()
                if user:
                    db.delete(user)
            db.commit()
        finally:
            db.close()
    
    def simulate_user_session(self, user_index: int, duration: int = 30):
        """Simulate a single user session with various API calls"""
        user_data = self.test_users[user_index]
        headers = {"Authorization": f"Bearer {user_data['token']}"} if user_data["token"] else {}
        
        results = {
            "user_index": user_index,
            "requests": 0,
            "successful": 0,
            "failed": 0,
            "errors": [],
            "response_times": []
        }
        
        start_time = time.time()
        
        # Simulate user actions for specified duration
        while time.time() - start_time < duration:
            try:
                # Random action selection
                action = random.choice([
                    "dashboard",
                    "port_scan",
                    "cve_search",
                    "exploit_search",
                    "profile"
                ])
                
                request_start = time.time()
                
                if action == "dashboard":
                    response = client.get("/api/dashboard/stats", headers=headers)
                
                elif action == "port_scan":
                    response = client.post("/api/scanning/port-scan", 
                        json={
                            "target": "scanme.nmap.org",
                            "ports": "80,443",
                            "scan_type": "quick"
                        },
                        headers=headers
                    )
                
                elif action == "cve_search":
                    response = client.get(
                        "/api/cve/search",
                        params={"query": "apache", "limit": 10},
                        headers=headers
                    )
                
                elif action == "exploit_search":
                    response = client.get(
                        "/api/exploits/search",
                        params={"query": "windows", "limit": 10},
                        headers=headers
                    )
                
                elif action == "profile":
                    response = client.get("/api/auth/me", headers=headers)
                
                request_time = time.time() - request_start
                results["response_times"].append(request_time)
                results["requests"] += 1
                
                if response.status_code in [200, 201, 202]:
                    results["successful"] += 1
                else:
                    results["failed"] += 1
                    results["errors"].append(f"{action}: {response.status_code}")
                
                # Small delay between requests
                time.sleep(random.uniform(0.5, 2.0))
                
            except Exception as e:
                results["failed"] += 1
                results["errors"].append(f"Exception: {str(e)}")
        
        return results
    
    def test_2_concurrent_users(self):
        """Test system with 2 concurrent users"""
        print("\n" + "="*60)
        print("LOAD TEST: 2 Concurrent Users")
        print("="*60)
        
        duration = 20  # 20 seconds per user
        
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(self.simulate_user_session, 0, duration),
                executor.submit(self.simulate_user_session, 1, duration)
            ]
            
            results = [future.result() for future in as_completed(futures)]
        
        # Analyze results
        total_requests = sum(r["requests"] for r in results)
        total_successful = sum(r["successful"] for r in results)
        total_failed = sum(r["failed"] for r in results)
        all_response_times = []
        for r in results:
            all_response_times.extend(r["response_times"])
        
        avg_response_time = sum(all_response_times) / len(all_response_times) if all_response_times else 0
        max_response_time = max(all_response_times) if all_response_times else 0
        min_response_time = min(all_response_times) if all_response_times else 0
        
        print(f"\nResults for 2 Users:")
        print(f"  Total Requests: {total_requests}")
        print(f"  Successful: {total_successful} ({total_successful/total_requests*100:.1f}%)")
        print(f"  Failed: {total_failed} ({total_failed/total_requests*100:.1f}%)")
        print(f"  Avg Response Time: {avg_response_time:.3f}s")
        print(f"  Min Response Time: {min_response_time:.3f}s")
        print(f"  Max Response Time: {max_response_time:.3f}s")
        
        for i, result in enumerate(results):
            print(f"\n  User {i}:")
            print(f"    Requests: {result['requests']}")
            print(f"    Success Rate: {result['successful']/result['requests']*100:.1f}%")
            if result['errors']:
                print(f"    Errors: {result['errors'][:3]}")
        
        # Assertions
        assert total_successful > 0, "No successful requests"
        assert total_successful / total_requests >= 0.8, "Success rate below 80%"
        assert avg_response_time < 5.0, "Average response time too high"
    
    def test_3_concurrent_users(self):
        """Test system with 3 concurrent users"""
        print("\n" + "="*60)
        print("LOAD TEST: 3 Concurrent Users")
        print("="*60)
        
        duration = 20  # 20 seconds per user
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(self.simulate_user_session, 0, duration),
                executor.submit(self.simulate_user_session, 1, duration),
                executor.submit(self.simulate_user_session, 2, duration)
            ]
            
            results = [future.result() for future in as_completed(futures)]
        
        # Analyze results
        total_requests = sum(r["requests"] for r in results)
        total_successful = sum(r["successful"] for r in results)
        total_failed = sum(r["failed"] for r in results)
        all_response_times = []
        for r in results:
            all_response_times.extend(r["response_times"])
        
        avg_response_time = sum(all_response_times) / len(all_response_times) if all_response_times else 0
        max_response_time = max(all_response_times) if all_response_times else 0
        min_response_time = min(all_response_times) if all_response_times else 0
        
        print(f"\nResults for 3 Users:")
        print(f"  Total Requests: {total_requests}")
        print(f"  Successful: {total_successful} ({total_successful/total_requests*100:.1f}%)")
        print(f"  Failed: {total_failed} ({total_failed/total_requests*100:.1f}%)")
        print(f"  Avg Response Time: {avg_response_time:.3f}s")
        print(f"  Min Response Time: {min_response_time:.3f}s")
        print(f"  Max Response Time: {max_response_time:.3f}s")
        
        for i, result in enumerate(results):
            print(f"\n  User {i}:")
            print(f"    Requests: {result['requests']}")
            print(f"    Success Rate: {result['successful']/result['requests']*100:.1f}%")
            if result['errors']:
                print(f"    Errors: {result['errors'][:3]}")
        
        # Assertions
        assert total_successful > 0, "No successful requests"
        assert total_successful / total_requests >= 0.75, "Success rate below 75%"
        assert avg_response_time < 10.0, "Average response time too high"
    
    def test_concurrent_database_operations(self):
        """Test concurrent database writes"""
        print("\n" + "="*60)
        print("LOAD TEST: Concurrent Database Operations")
        print("="*60)
        
        def create_scan_record(user_index):
            """Create a scan record"""
            user_data = self.test_users[user_index]
            headers = {"Authorization": f"Bearer {user_data['token']}"} if user_data["token"] else {}
            
            response = client.post(
                "/api/scanning/port-scan",
                json={
                    "target": f"192.168.1.{random.randint(1, 254)}",
                    "ports": "80,443,8080",
                    "scan_type": "quick"
                },
                headers=headers
            )
            return response.status_code in [200, 201, 202]
        
        # Simulate 3 users creating scans simultaneously
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(create_scan_record, i) for i in range(3)]
            results = [future.result() for future in as_completed(futures)]
        
        successful = sum(results)
        print(f"\n  Concurrent DB Writes: {len(results)}")
        print(f"  Successful: {successful} ({successful/len(results)*100:.1f}%)")
        
        assert successful >= 2, "Too many failed database operations"
    
    def test_rate_limiting_under_load(self):
        """Test rate limiting with concurrent users"""
        print("\n" + "="*60)
        print("LOAD TEST: Rate Limiting Under Load")
        print("="*60)
        
        user_data = self.test_users[0]
        headers = {"Authorization": f"Bearer {user_data['token']}"} if user_data["token"] else {}
        
        def make_rapid_requests(count):
            """Make rapid requests to trigger rate limit"""
            status_codes = []
            for _ in range(count):
                response = client.get("/api/dashboard/stats", headers=headers)
                status_codes.append(response.status_code)
            return status_codes
        
        # Make 50 rapid requests from single user
        status_codes = make_rapid_requests(50)
        
        rate_limited = sum(1 for code in status_codes if code == 429)
        successful = sum(1 for code in status_codes if code == 200)
        
        print(f"\n  Total Requests: {len(status_codes)}")
        print(f"  Successful: {successful}")
        print(f"  Rate Limited (429): {rate_limited}")
        
        assert rate_limited > 0, "Rate limiting not working"
        print("\n  ✓ Rate limiting is functional")


class TestResourceUtilization:
    """Test resource usage under load"""
    
    def test_memory_leak_detection(self):
        """Test for memory leaks during sustained load"""
        print("\n" + "="*60)
        print("RESOURCE TEST: Memory Leak Detection")
        print("="*60)
        
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Make 100 requests
        for i in range(100):
            response = client.get("/api/cve/search?query=test&limit=10")
            if i % 20 == 0:
                current_memory = process.memory_info().rss / 1024 / 1024
                print(f"  Request {i}: Memory usage: {current_memory:.2f} MB")
        
        final_memory = process.memory_info().rss / 1024 / 1024
        memory_increase = final_memory - initial_memory
        
        print(f"\n  Initial Memory: {initial_memory:.2f} MB")
        print(f"  Final Memory: {final_memory:.2f} MB")
        print(f"  Increase: {memory_increase:.2f} MB")
        
        # Allow up to 100MB increase
        assert memory_increase < 100, f"Possible memory leak: {memory_increase:.2f}MB increase"
        print("\n  ✓ No significant memory leak detected")


class TestEndpointPerformance:
    """Test individual endpoint performance"""
    
    def test_critical_endpoints_response_time(self):
        """Test response time of critical endpoints"""
        print("\n" + "="*60)
        print("PERFORMANCE TEST: Critical Endpoints")
        print("="*60)
        
        endpoints = {
            "Health Check": ("/health", "GET", None),
            "Dashboard": ("/api/dashboard/stats", "GET", None),
            "CVE Search": ("/api/cve/search?query=apache&limit=5", "GET", None),
            "Exploit Search": ("/api/exploits/search?query=windows&limit=5", "GET", None),
        }
        
        results = {}
        
        for name, (path, method, data) in endpoints.items():
            times = []
            for _ in range(10):
                start = time.time()
                if method == "GET":
                    response = client.get(path)
                else:
                    response = client.post(path, json=data)
                elapsed = time.time() - start
                times.append(elapsed)
            
            avg_time = sum(times) / len(times)
            max_time = max(times)
            min_time = min(times)
            
            results[name] = {
                "avg": avg_time,
                "max": max_time,
                "min": min_time
            }
            
            print(f"\n  {name}:")
            print(f"    Avg: {avg_time*1000:.2f}ms")
            print(f"    Min: {min_time*1000:.2f}ms")
            print(f"    Max: {max_time*1000:.2f}ms")
        
        # Assert all endpoints respond within acceptable time
        for name, times in results.items():
            assert times["avg"] < 2.0, f"{name} average response time too high: {times['avg']}s"
        
        print("\n  ✓ All endpoints within acceptable response time")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
