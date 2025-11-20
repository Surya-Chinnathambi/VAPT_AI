"""
Simplified Load Test - Tests 2-3 concurrent users without full dependencies
Run this independently: python tests/test_simple_load.py
"""

import asyncio
import aiohttp
import time
import random
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict

# Configuration
BASE_URL = "http://localhost:8000"
NUM_USERS_TEST_1 = 2
NUM_USERS_TEST_2 = 3
TEST_DURATION = 15  # seconds per user


class LoadTestResults:
    def __init__(self):
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.response_times = []
        self.errors = []
    
    def add_result(self, success: bool, response_time: float, error: str = None):
        self.total_requests += 1
        if success:
            self.successful_requests += 1
        else:
            self.failed_requests += 1
            if error:
                self.errors.append(error)
        self.response_times.append(response_time)
    
    def get_stats(self) -> Dict:
        if not self.response_times:
            return {}
        
        return {
            "total_requests": self.total_requests,
            "successful": self.successful_requests,
            "failed": self.failed_requests,
            "success_rate": (self.successful_requests / self.total_requests * 100) if self.total_requests > 0 else 0,
            "avg_response_time": sum(self.response_times) / len(self.response_times),
            "min_response_time": min(self.response_times),
            "max_response_time": max(self.response_times),
            "errors_sample": self.errors[:5]
        }


async def simulate_user_session(user_id: int, duration: int) -> LoadTestResults:
    """Simulate a single user session"""
    results = LoadTestResults()
    start_time = time.time()
    
    # Endpoints to test (public endpoints that don't require auth)
    endpoints = [
        ("/health", "GET"),
        ("/docs", "GET"),
        ("/", "GET"),  # Root endpoint
    ]
    
    async with aiohttp.ClientSession() as session:
        while time.time() - start_time < duration:
            # Random endpoint selection
            endpoint, method = random.choice(endpoints)
            
            request_start = time.time()
            try:
                if method == "GET":
                    async with session.get(f"{BASE_URL}{endpoint}", timeout=10) as response:
                        await response.text()
                        success = response.status in [200, 201]
                        response_time = time.time() - request_start
                        results.add_result(
                            success,
                            response_time,
                            f"{endpoint}: {response.status}" if not success else None
                        )
            except Exception as e:
                response_time = time.time() - request_start
                results.add_result(False, response_time, f"{endpoint}: {str(e)}")
            
            # Random delay between requests (0.5 - 2 seconds)
            await asyncio.sleep(random.uniform(0.5, 2.0))
    
    return results


def run_concurrent_users_test(num_users: int, duration: int):
    """Run test with specified number of concurrent users"""
    print("\n" + "="*70)
    print(f"LOAD TEST: {num_users} Concurrent Users ({duration}s each)")
    print("="*70)
    
    # Run concurrent sessions
    async def run_all_sessions():
        tasks = [simulate_user_session(i, duration) for i in range(num_users)]
        return await asyncio.gather(*tasks)
    
    # Execute
    start_time = time.time()
    all_results = asyncio.run(run_all_sessions())
    total_time = time.time() - start_time
    
    # Aggregate results
    print(f"\n📊 Test completed in {total_time:.2f}s")
    print("\nPer-User Results:")
    print("-" * 70)
    
    total_requests = 0
    total_successful = 0
    total_failed = 0
    all_response_times = []
    
    for i, result in enumerate(all_results):
        stats = result.get_stats()
        total_requests += stats["total_requests"]
        total_successful += stats["successful"]
        total_failed += stats["failed"]
        all_response_times.extend(result.response_times)
        
        print(f"\nUser {i+1}:")
        print(f"  Requests: {stats['total_requests']}")
        print(f"  Success Rate: {stats['success_rate']:.1f}%")
        print(f"  Avg Response Time: {stats['avg_response_time']*1000:.0f}ms")
        print(f"  Min/Max Response: {stats['min_response_time']*1000:.0f}ms / {stats['max_response_time']*1000:.0f}ms")
        if stats['errors_sample']:
            print(f"  Errors: {', '.join(stats['errors_sample'][:2])}")
    
    # Overall statistics
    print("\n" + "="*70)
    print("OVERALL RESULTS:")
    print("="*70)
    print(f"Total Requests: {total_requests}")
    print(f"Successful: {total_successful} ({total_successful/total_requests*100:.1f}%)")
    print(f"Failed: {total_failed} ({total_failed/total_requests*100:.1f}%)")
    
    if all_response_times:
        avg_time = sum(all_response_times) / len(all_response_times)
        print(f"Avg Response Time: {avg_time*1000:.0f}ms")
        print(f"Min Response Time: {min(all_response_times)*1000:.0f}ms")
        print(f"Max Response Time: {max(all_response_times)*1000:.0f}ms")
        print(f"Requests/Second: {total_requests/total_time:.2f}")
    
    # Assessment
    print("\n" + "="*70)
    print("DEPLOYMENT READINESS ASSESSMENT:")
    print("="*70)
    
    success_rate = total_successful / total_requests * 100 if total_requests > 0 else 0
    avg_response = sum(all_response_times) / len(all_response_times) if all_response_times else 0
    
    checks = []
    checks.append(("Success Rate > 80%", success_rate > 80, f"{success_rate:.1f}%"))
    checks.append(("Avg Response < 3s", avg_response < 3.0, f"{avg_response*1000:.0f}ms"))
    checks.append(("Max Response < 10s", max(all_response_times) < 10.0 if all_response_times else False, 
                   f"{max(all_response_times)*1000:.0f}ms" if all_response_times else "N/A"))
    checks.append(("No Critical Errors", total_failed < total_requests * 0.2, 
                   f"{total_failed} failures"))
    
    all_passed = True
    for check_name, passed, value in checks:
        status = "✓" if passed else "✗"
        color = "PASS" if passed else "FAIL"
        print(f"{status} {check_name}: {value} [{color}]")
        if not passed:
            all_passed = False
    
    print("\n" + "="*70)
    if all_passed:
        print("🎉 SYSTEM READY FOR DEPLOYMENT WITH 2-3 USERS! 🎉")
    else:
        print("⚠️  SOME CHECKS FAILED - REVIEW BEFORE DEPLOYMENT")
    print("="*70 + "\n")
    
    return all_passed


def test_server_availability():
    """Test if backend server is running"""
    print("\n🔍 Checking Backend Availability...")
    
    import requests
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        if response.status_code == 200:
            print("✓ Backend server is running")
            return True
        else:
            print(f"✗ Backend returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"✗ Backend not accessible: {str(e)}")
        print("\nPlease start the backend server:")
        print("  cd backend")
        print("  uvicorn main:app --reload")
        return False


if __name__ == "__main__":
    print("="*70)
    print("CyberShield AI - Concurrent User Load Testing")
    print("="*70)
    
    # Check server availability
    if not test_server_availability():
        exit(1)
    
    # Run tests
    test1_passed = run_concurrent_users_test(NUM_USERS_TEST_1, TEST_DURATION)
    test2_passed = run_concurrent_users_test(NUM_USERS_TEST_2, TEST_DURATION)
    
    # Final summary
    print("\n" + "="*70)
    print("FINAL SUMMARY:")
    print("="*70)
    print(f"2 Users Test: {'✓ PASSED' if test1_passed else '✗ FAILED'}")
    print(f"3 Users Test: {'✓ PASSED' if test2_passed else '✗ FAILED'}")
    
    if test1_passed and test2_passed:
        print("\n🚀 READY FOR PRODUCTION DEPLOYMENT! 🚀")
        print("\nRecommended next steps:")
        print("  1. Deploy using docker-compose -f docker-compose.prod.yml up -d")
        print("  2. Configure SSL/TLS certificates")
        print("  3. Set up monitoring (Sentry, Prometheus)")
        print("  4. Configure automated backups")
        print("  5. Run security audit")
    else:
        print("\n⚠️  ADDRESS ISSUES BEFORE DEPLOYMENT")
        print("\nReview the test output above for specific failures")
    
    print("="*70)
    
    exit(0 if test1_passed and test2_passed else 1)
