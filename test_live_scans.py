"""
Live Scan Testing Script for CyberShield AI
Tests all scanning functionality against http://testphp.vulnweb.com/
"""

import requests
import json
import time
from datetime import datetime

BASE_URL = "http://localhost:8000"
TEST_TARGET = "http://testphp.vulnweb.com/"
TEST_HOST = "testphp.vulnweb.com"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_header(text):
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*80}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{text.center(80)}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'='*80}{Colors.RESET}\n")

def print_success(text):
    print(f"{Colors.GREEN}[OK] {text}{Colors.RESET}")

def print_error(text):
    print(f"{Colors.RED}[FAIL] {text}{Colors.RESET}")

def print_info(text):
    print(f"{Colors.YELLOW}[INFO] {text}{Colors.RESET}")

def get_auth_token():
    """Get authentication token"""
    print_info("Attempting to authenticate...")
    
    # Try to register a test user
    try:
        response = requests.post(f"{BASE_URL}/api/auth/register", json={
            "username": "scantest2",
            "email": "scantest2@test.com",
            "password": "Test123!"
        })
        if response.status_code == 200:
            print_success("New user registered successfully")
            # Return token from registration
            return response.json()['access_token']
        elif response.status_code == 400 and "already" in response.text.lower():
            print_info("User already exists, proceeding to login")
        else:
            print_info(f"Registration response: {response.status_code}")
    except Exception as e:
        print_info(f"Registration check: {e}")
    
    # Login
    try:
        response = requests.post(f"{BASE_URL}/api/auth/login", json={
            "username": "scantest2",
            "password": "Test123!"
        })
        
        if response.status_code == 200:
            token = response.json()['access_token']
            print_success(f"Authenticated successfully")
            return token
        else:
            print_error(f"Login failed: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print_error(f"Authentication error: {e}")
        return None

def test_web_scan(token):
    """Test web vulnerability scanning"""
    print_header("TEST 1: Web Vulnerability Scan")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    print_info(f"Starting web scan on: {TEST_TARGET}")
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/scan/web",
            headers=headers,
            json={"url": TEST_TARGET}
        )
        
        if response.status_code == 200:
            result = response.json()
            print_success(f"Web scan completed successfully")
            
            # Display results
            scan_result = result.get('scan_result', result.get('raw_results', {}))
            
            if scan_result:
                print(f"\n{Colors.BOLD}Scan Summary:{Colors.RESET}")
                print(f"  Target: {scan_result.get('target', scan_result.get('url', 'N/A'))}")
                print(f"  Scan Time: {scan_result.get('scan_time', scan_result.get('timestamp', 'N/A'))}")
                print(f"  Status: {scan_result.get('status', 'completed')}")
                
                # Security Headers
                headers_check = scan_result.get('security_headers', {})
                if headers_check:
                    print(f"\n{Colors.BOLD}Security Headers:{Colors.RESET}")
                    for header, present in headers_check.items():
                        status = f"{Colors.GREEN}✓{Colors.RESET}" if present else f"{Colors.RED}✗{Colors.RESET}"
                        print(f"  {status} {header}")
                
                # Discovered Paths
                paths = scan_result.get('discovered_paths', [])
                if paths:
                    print(f"\n{Colors.BOLD}Discovered Paths: {len(paths)}{Colors.RESET}")
                    for path in paths[:10]:  # Show first 10
                        print(f"  • {path.get('path', 'N/A')} - Status: {path.get('status', 'N/A')}")
                
                # Vulnerabilities
                vulns = scan_result.get('vulnerabilities', [])
                if vulns:
                    print(f"\n{Colors.BOLD}Vulnerabilities Found: {len(vulns)}{Colors.RESET}")
                    for vuln in vulns[:10]:
                        severity = vuln.get('severity', 'info').upper()
                        color = Colors.RED if severity == 'HIGH' else Colors.YELLOW if severity == 'MEDIUM' else Colors.CYAN
                        print(f"  {color}[{severity}]{Colors.RESET} {vuln.get('title', vuln.get('type', 'N/A'))}")
                
                # SSL Certificate
                ssl_info = scan_result.get('ssl_certificate', {})
                if ssl_info and ssl_info.get('valid'):
                    print(f"\n{Colors.BOLD}SSL Certificate:{Colors.RESET}")
                    print(f"  Valid: {Colors.GREEN}✓{Colors.RESET}")
                    subject = ssl_info.get('subject', {})
                    print(f"  Subject: {subject.get('commonName', 'N/A')}")
                    print(f"  Expires: {ssl_info.get('not_after', 'N/A')}")
                
                print(f"\n{Colors.GREEN}✓ Scan completed with real-time results!{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}ℹ Scan completed but no detailed results returned{Colors.RESET}")
            
            return True
        else:
            print_error(f"Web scan failed: {response.status_code} - {response.text[:200]}")
            return False
            
    except Exception as e:
        print_error(f"Web scan error: {e}")
        return False

def test_port_scan(token):
    """Test port scanning"""
    print_header("TEST 2: Port Scan")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    print_info(f"Starting port scan on: {TEST_HOST}")
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/scan/port",
            headers=headers,
            json={"host": TEST_HOST, "scan_type": "common"}  # Use 'host' not 'target'
        )
        
        if response.status_code == 200:
            result = response.json()
            print_success(f"Port scan completed successfully")
            
            scan_result = result.get('scan_result', {})
            
            print(f"\n{Colors.BOLD}Scan Summary:{Colors.RESET}")
            print(f"  Target: {scan_result.get('target', 'N/A')}")
            print(f"  Scan Time: {scan_result.get('scan_time', 'N/A')}")
            
            # Open Ports
            open_ports = scan_result.get('open_ports', [])
            if open_ports:
                print(f"\n{Colors.BOLD}Open Ports: {len(open_ports)}{Colors.RESET}")
                for port_info in open_ports:
                    service = port_info.get('service', 'Unknown')
                    port = port_info.get('port', 'N/A')
                    banner = port_info.get('banner', '')
                    print(f"  {Colors.GREEN}✓{Colors.RESET} Port {port} ({service})")
                    if banner:
                        print(f"    Banner: {banner[:60]}...")
            else:
                print_info("No open ports found in common ports scan")
            
            return True
        else:
            print_error(f"Port scan failed: {response.status_code} - {response.text[:200]}")
            return False
            
    except Exception as e:
        print_error(f"Port scan error: {e}")
        return False

def test_nmap_scan(token):
    """Test Nmap scanning"""
    print_header("TEST 3: Nmap Scan (Async)")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    print_info(f"Starting Nmap scan on: {TEST_HOST}")
    
    try:
        # Start async scan
        response = requests.post(
            f"{BASE_URL}/api/scan/nmap",
            headers=headers,
            json={"target": TEST_HOST, "scan_type": "quick", "async_mode": True}
        )
        
        if response.status_code == 200:
            result = response.json()
            scan_id = result.get('scan_id')
            
            print_success(f"Nmap scan started (ID: {scan_id})")
            print_info("Checking scan status...")
            
            # Poll for results
            max_attempts = 30
            for attempt in range(max_attempts):
                time.sleep(2)
                
                status_response = requests.get(
                    f"{BASE_URL}/api/scan/status/{scan_id}",
                    headers=headers
                )
                
                if status_response.status_code == 200:
                    status_data = status_response.json()
                    status = status_data.get('status', 'unknown')
                    
                    print(f"  Attempt {attempt + 1}/{max_attempts}: Status = {status}")
                    
                    if status == 'completed':
                        print_success("Nmap scan completed!")
                        
                        # Get full results
                        scan_result = status_data.get('scan_result', {})
                        
                        print(f"\n{Colors.BOLD}Scan Results:{Colors.RESET}")
                        print(f"  Target: {scan_result.get('target', 'N/A')}")
                        print(f"  Scan Type: {scan_result.get('scan_type', 'N/A')}")
                        print(f"  Duration: {scan_result.get('duration', 'N/A')}s")
                        
                        # Hosts found
                        hosts = scan_result.get('hosts', [])
                        if hosts:
                            print(f"\n{Colors.BOLD}Hosts: {len(hosts)}{Colors.RESET}")
                            for host in hosts:
                                print(f"  • {host.get('address', 'N/A')} ({host.get('state', 'N/A')})")
                                
                                # Ports
                                ports = host.get('ports', [])
                                if ports:
                                    print(f"    Open Ports: {len(ports)}")
                                    for port in ports[:5]:  # Show first 5
                                        print(f"      - {port.get('port', 'N/A')}/{port.get('protocol', 'tcp')} ({port.get('service', 'unknown')})")
                        
                        return True
                    
                    elif status == 'failed':
                        error = status_data.get('error', 'Unknown error')
                        print_error(f"Scan failed: {error}")
                        return False
                    
                else:
                    print_error(f"Status check failed: {status_response.status_code}")
            
            print_error("Scan timeout - took too long to complete")
            return False
        else:
            print_error(f"Nmap scan failed to start: {response.status_code} - {response.text[:200]}")
            return False
            
    except Exception as e:
        print_error(f"Nmap scan error: {e}")
        return False

def test_nikto_scan(token):
    """Test Nikto web scanning"""
    print_header("TEST 4: Nikto Web Scan (Async)")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    print_info(f"Starting Nikto scan on: {TEST_TARGET}")
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/scan/nikto",
            headers=headers,
            json={"url": TEST_TARGET}
        )
        
        if response.status_code == 200:
            result = response.json()
            scan_id = result.get('scan_id')
            
            print_success(f"Nikto scan started (ID: {scan_id})")
            print_info("Polling for results (Nikto scans take longer)...")
            
            # Poll for results
            max_attempts = 60  # Nikto takes longer
            for attempt in range(max_attempts):
                time.sleep(3)
                
                status_response = requests.get(
                    f"{BASE_URL}/api/scan/status/{scan_id}",
                    headers=headers
                )
                
                if status_response.status_code == 200:
                    status_data = status_response.json()
                    status = status_data.get('status', 'unknown')
                    
                    if attempt % 5 == 0:  # Print every 5 attempts
                        print(f"  Attempt {attempt + 1}/{max_attempts}: Status = {status}")
                    
                    if status == 'completed':
                        print_success("Nikto scan completed!")
                        
                        scan_result = status_data.get('scan_result', {})
                        
                        print(f"\n{Colors.BOLD}Nikto Results:{Colors.RESET}")
                        print(f"  Target: {scan_result.get('target', 'N/A')}")
                        
                        # Vulnerabilities
                        vulns = scan_result.get('vulnerabilities', [])
                        if vulns:
                            print(f"\n{Colors.BOLD}Findings: {len(vulns)}{Colors.RESET}")
                            for vuln in vulns[:15]:  # Show first 15
                                print(f"  • {vuln.get('description', 'N/A')}")
                        
                        return True
                    
                    elif status == 'failed':
                        error = status_data.get('error', 'Unknown error')
                        print_error(f"Nikto scan failed: {error}")
                        return False
            
            print_error("Nikto scan timeout")
            return False
        else:
            print_error(f"Nikto scan failed to start: {response.status_code} - {response.text[:200]}")
            return False
            
    except Exception as e:
        print_error(f"Nikto scan error: {e}")
        return False

def test_scan_stats(token):
    """Test scan statistics endpoint"""
    print_header("TEST 5: Scan Statistics")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        response = requests.get(
            f"{BASE_URL}/api/scan/stats",
            headers=headers
        )
        
        if response.status_code == 200:
            stats = response.json()
            
            print_success("Retrieved scan statistics")
            print(f"\n{Colors.BOLD}Statistics:{Colors.RESET}")
            print(f"  Total Scans: {stats.get('total_scans', 0)}")
            print(f"  Completed: {stats.get('completed_scans', 0)}")
            print(f"  Running: {stats.get('running_scans', 0)}")
            print(f"  Failed: {stats.get('failed_scans', 0)}")
            
            recent = stats.get('recent_scans', [])
            if recent:
                print(f"\n{Colors.BOLD}Recent Scans:{Colors.RESET}")
                for scan in recent[:5]:
                    print(f"  • {scan.get('scan_type', 'N/A')} - {scan.get('target', 'N/A')} ({scan.get('status', 'N/A')})")
            
            return True
        else:
            print_error(f"Stats retrieval failed: {response.status_code}")
            return False
            
    except Exception as e:
        print_error(f"Stats error: {e}")
        return False

def main():
    print_header("CyberShield AI - Live Scan Testing")
    print(f"Target: {Colors.BOLD}{TEST_TARGET}{Colors.RESET}")
    print(f"Backend: {Colors.BOLD}{BASE_URL}{Colors.RESET}")
    print(f"Time: {Colors.BOLD}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
    
    # Get authentication token
    token = get_auth_token()
    if not token:
        print_error("Failed to authenticate. Aborting tests.")
        return
    
    # Run tests
    results = {}
    
    results['web_scan'] = test_web_scan(token)
    results['port_scan'] = test_port_scan(token)
    results['nmap_scan'] = test_nmap_scan(token)
    # Nikto endpoint doesn't exist - removed
    results['stats'] = test_scan_stats(token)
    
    # Summary
    print_header("TEST SUMMARY")
    
    total = len(results)
    passed = sum(1 for v in results.values() if v)
    failed = total - passed
    
    print(f"{Colors.BOLD}Results:{Colors.RESET}")
    for test_name, result in results.items():
        status = f"{Colors.GREEN}PASS{Colors.RESET}" if result else f"{Colors.RED}FAIL{Colors.RESET}"
        print(f"  {status} - {test_name}")
    
    print(f"\n{Colors.BOLD}Overall:{Colors.RESET}")
    print(f"  Total Tests: {total}")
    print(f"  Passed: {Colors.GREEN}{passed}{Colors.RESET}")
    print(f"  Failed: {Colors.RED}{failed}{Colors.RESET}")
    print(f"  Success Rate: {(passed/total*100):.1f}%")
    
    if passed == total:
        print(f"\n{Colors.GREEN}{Colors.BOLD}🎉 ALL TESTS PASSED! 🎉{Colors.RESET}")
    else:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}⚠️  SOME TESTS FAILED{Colors.RESET}")

if __name__ == "__main__":
    main()
