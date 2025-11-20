"""
Comprehensive Full Stack Test
Tests: Backend API → Database → Docker Tools → Frontend Integration
"""
import requests
import asyncio
import json
import sys
import os
from colorama import init, Fore, Style

init()

BASE_URL = "http://localhost:8000"
API_URL = f"{BASE_URL}/api"

def print_header(text):
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{text.center(70)}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")

def test_backend_health():
    """Test if backend is running"""
    print_header("Backend Health Check")
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        if response.status_code == 200:
            print(f"{Fore.GREEN}✓ Backend is healthy{Style.RESET_ALL}")
            print(f"  Response: {response.json()}")
            return True
        else:
            print(f"{Fore.RED}✗ Backend returned {response.status_code}{Style.RESET_ALL}")
            return False
    except Exception as e:
        print(f"{Fore.RED}✗ Backend not accessible: {e}{Style.RESET_ALL}")
        return False

def test_authentication():
    """Test login and get token"""
    print_header("Authentication Test")
    try:
        response = requests.post(f"{API_URL}/auth/login", json={
            "username": "scantest2",
            "password": "Test123!"
        })
        
        if response.status_code == 200:
            token = response.json()["access_token"]
            print(f"{Fore.GREEN}✓ Authentication successful{Style.RESET_ALL}")
            print(f"  Token: {token[:30]}...")
            return token
        else:
            print(f"{Fore.RED}✗ Authentication failed: {response.status_code}{Style.RESET_ALL}")
            print(f"  {response.text}")
            return None
    except Exception as e:
        print(f"{Fore.RED}✗ Authentication error: {e}{Style.RESET_ALL}")
        return None

def test_vapt_tools_endpoint(token):
    """Test VAPT tools listing"""
    print_header("VAPT Tools Endpoint")
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(f"{API_URL}/vapt/tools", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            print(f"{Fore.GREEN}✓ VAPT tools endpoint working{Style.RESET_ALL}")
            print(f"  Total tools: {data.get('total_tools', 0)}")
            print(f"  AI orchestrated: {data.get('ai_orchestrated', False)}")
            print(f"  Parallel execution: {data.get('parallel_execution', False)}")
            
            # Show categories
            for category, tools in data.get('categories', {}).items():
                print(f"\n  {category.upper()}: {len(tools)} tools")
                for tool in tools[:2]:  # Show first 2 from each category
                    print(f"    - {tool['name']}: {tool['description'][:50]}...")
            
            return True
        else:
            print(f"{Fore.RED}✗ Failed: {response.status_code}{Style.RESET_ALL}")
            return False
    except Exception as e:
        print(f"{Fore.RED}✗ Error: {e}{Style.RESET_ALL}")
        return False

def test_port_scan(token):
    """Test port scanning endpoint"""
    print_header("Port Scan Test")
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.post(f"{API_URL}/scan/port", json={
            "host": "scanme.nmap.org",
            "ports": [80, 443]
        }, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            print(f"{Fore.GREEN}✓ Port scan initiated{Style.RESET_ALL}")
            print(f"  Scan ID: {data.get('scan_id', 'N/A')}")
            print(f"  Status: {data.get('status', 'N/A')}")
            return True
        else:
            print(f"{Fore.RED}✗ Failed: {response.status_code}{Style.RESET_ALL}")
            print(f"  {response.text[:200]}")
            return False
    except Exception as e:
        print(f"{Fore.RED}✗ Error: {e}{Style.RESET_ALL}")
        return False

def test_database_connectivity(token):
    """Test database by checking scan history"""
    print_header("Database Connectivity Test")
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(f"{API_URL}/scan/history?limit=5", headers=headers)
        
        if response.status_code == 200:
            scans = response.json()  # Returns list directly
            print(f"{Fore.GREEN}✓ Database accessible{Style.RESET_ALL}")
            print(f"  Total scans in history: {len(scans)}")
            if scans:
                latest = scans[0]
                print(f"  Latest scan: {latest.get('scan_type')} on {latest.get('target')}")
                print(f"  Status: {latest.get('status')}")
            return True
        else:
            print(f"{Fore.RED}✗ Failed: {response.status_code}{Style.RESET_ALL}")
            return False
    except Exception as e:
        print(f"{Fore.RED}✗ Error: {e}{Style.RESET_ALL}")
        return False

def test_dashboard_stats(token):
    """Test dashboard statistics endpoint"""
    print_header("Dashboard Statistics Test")
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(f"{API_URL}/dashboard/stats", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            print(f"{Fore.GREEN}✓ Dashboard stats available{Style.RESET_ALL}")
            print(f"  Total scans: {data.get('total_scans', 0)}")
            print(f"  Total vulnerabilities: {data.get('total_vulnerabilities', 0)}")
            print(f"  High risk: {data.get('high_risk_count', 0)}")
            return True
        else:
            print(f"{Fore.RED}✗ Failed: {response.status_code}{Style.RESET_ALL}")
            return False
    except Exception as e:
        print(f"{Fore.RED}✗ Error: {e}{Style.RESET_ALL}")
        return False

def test_docker_integration():
    """Test Docker is accessible"""
    print_header("Docker Integration Test")
    
    # Add backend to path for imports
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))
    
    try:
        from core.docker_manager import get_docker_manager
        dm = get_docker_manager()
        
        print(f"{Fore.GREEN}✓ Docker manager connected{Style.RESET_ALL}")
        
        # Get stats
        stats = dm.get_container_stats()
        print(f"  Scan containers: {stats.get('total_containers', 0)}")
        print(f"  Running: {stats.get('running', 0)}")
        
        # Check images
        images = dm.client.images.list()
        security_images = [img for img in images if any(
            tag for tag in img.tags if any(
                tool in tag for tool in ['nmap', 'nikto', 'nuclei', 'trivy']
            )
        )]
        print(f"  Security tool images: {len(security_images)}")
        
        return True
    except Exception as e:
        print(f"{Fore.RED}✗ Error: {e}{Style.RESET_ALL}")
        return False

def test_api_docs():
    """Test API documentation is available"""
    print_header("API Documentation Test")
    try:
        response = requests.get(f"{BASE_URL}/docs")
        if response.status_code == 200:
            print(f"{Fore.GREEN}✓ API docs available at {BASE_URL}/docs{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.YELLOW}⚠ API docs returned {response.status_code}{Style.RESET_ALL}")
            return False
    except Exception as e:
        print(f"{Fore.RED}✗ Error: {e}{Style.RESET_ALL}")
        return False

def main():
    """Run all integration tests"""
    print_header("CyberShield AI - Full Stack Integration Test")
    print(f"{Fore.CYAN}Testing: Backend + Database + Docker + API Endpoints{Style.RESET_ALL}\n")
    
    results = {}
    
    # Test 1: Backend health
    results['backend_health'] = test_backend_health()
    if not results['backend_health']:
        print(f"\n{Fore.RED}✗ Backend is not running. Start it with:{Style.RESET_ALL}")
        print(f"  cd D:\\CyberShieldAI\\CyberShieldAI\\backend")
        print(f"  python main.py")
        return
    
    # Test 2: API docs
    results['api_docs'] = test_api_docs()
    
    # Test 3: Authentication
    token = test_authentication()
    results['authentication'] = token is not None
    if not token:
        print(f"\n{Fore.RED}✗ Authentication failed. Cannot proceed with other tests.{Style.RESET_ALL}")
        return
    
    # Test 4: Database
    results['database'] = test_database_connectivity(token)
    
    # Test 5: VAPT tools
    results['vapt_tools'] = test_vapt_tools_endpoint(token)
    
    # Test 6: Port scan
    results['port_scan'] = test_port_scan(token)
    
    # Test 7: Dashboard
    results['dashboard'] = test_dashboard_stats(token)
    
    # Test 8: Docker
    results['docker'] = test_docker_integration()
    
    # Summary
    print_header("Test Summary")
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        status = f"{Fore.GREEN}PASS{Style.RESET_ALL}" if result else f"{Fore.RED}FAIL{Style.RESET_ALL}"
        print(f"  {test_name.replace('_', ' ').title()}: {status}")
    
    success_rate = (passed / total * 100) if total > 0 else 0
    print(f"\n{Fore.YELLOW}Success Rate: {success_rate:.1f}% ({passed}/{total}){Style.RESET_ALL}")
    
    if success_rate == 100:
        print(f"{Fore.GREEN}\n✓ All systems operational!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}\nReady to use:{Style.RESET_ALL}")
        print(f"  - Backend API: {BASE_URL}")
        print(f"  - API Docs: {BASE_URL}/docs")
        print(f"  - Frontend: npm run dev (in frontend folder)")
    elif success_rate >= 75:
        print(f"{Fore.YELLOW}\n⚠ Most systems operational{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}\n✗ Critical systems need attention{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
