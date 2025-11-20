"""
Real-time VAPT Scanner Test Client
Demonstrates WebSocket-based live scan results
"""
import asyncio
import websockets
import json
import requests
from datetime import datetime
import sys

API_URL = "http://localhost:8000"
TEST_TARGET = "testphp.vulnweb.com"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def print_header(text):
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*80}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{text.center(80)}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'='*80}{Colors.RESET}\n")


def print_success(text):
    print(f"{Colors.GREEN}✓ {text}{Colors.RESET}")


def print_error(text):
    print(f"{Colors.RED}✗ {text}{Colors.RESET}")


def print_info(text):
    print(f"{Colors.YELLOW}ℹ {text}{Colors.RESET}")


def print_vuln(text):
    print(f"{Colors.RED}🔥 {text}{Colors.RESET}")


def print_port(text):
    print(f"{Colors.GREEN}🔓 {text}{Colors.RESET}")


def get_auth_token():
    """Get authentication token"""
    try:
        response = requests.post(f"{API_URL}/api/auth/login", json={
            "username": "testscanner2",
            "password": "TestPassword123!"
        })
        
        if response.status_code == 200:
            return response.json()['access_token']
        else:
            # Try to register
            response = requests.post(f"{API_URL}/api/auth/register", json={
                "username": "testscanner2",
                "email": "testscanner2@example.com",
                "password": "TestPassword123!"
            })
            if response.status_code == 200:
                return response.json()['access_token']
    except Exception as e:
        print_error(f"Authentication failed: {e}")
    
    return None


async def realtime_nmap_scan(token: str, target: str, scan_type: str = "quick"):
    """Run real-time Nmap scan with WebSocket"""
    print_header(f"Real-time Nmap Scan: {target}")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        # Start the scan
        print_info(f"Starting {scan_type} Nmap scan...")
        response = requests.post(
            f"{API_URL}/api/realtime/scan/nmap/realtime",
            headers=headers,
            params={"target": target, "scan_type": scan_type}
        )
        
        if response.status_code != 200:
            print_error(f"Failed to start scan: {response.status_code} - {response.text}")
            return
        
        result = response.json()
        scan_id = result['scan_id']
        ws_url = result['websocket_url'].replace('localhost', '127.0.0.1')
        
        print_success(f"Scan started! ID: {scan_id}")
        print_info("Waiting for Docker container to initialize...")
        
        # Wait for Docker container to start
        await asyncio.sleep(3)
        
        # Connect to WebSocket
        print_info(f"Connecting to WebSocket...")
        async with websockets.connect(ws_url, open_timeout=10) as websocket:
            print_success("WebSocket connected! Streaming results...\n")
            
            stats = {
                "ports": 0,
                "vulnerabilities": 0,
                "logs": 0
            }
            
            while True:
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=180.0)
                    data = json.loads(message)
                    
                    msg_type = data.get('type')
                    timestamp = data.get('timestamp', '')
                    
                    if msg_type == "status":
                        status = data.get('status')
                        msg = data.get('message')
                        print(f"{Colors.CYAN}[STATUS]{Colors.RESET} {msg}")
                    
                    elif msg_type == "log":
                        log_msg = data.get('message', '')
                        stats['logs'] += 1
                        # Only show important logs
                        if any(keyword in log_msg.lower() for keyword in ['open', 'port', 'service', 'version', 'scan']):
                            print(f"{Colors.RESET}[LOG] {log_msg}{Colors.RESET}")
                    
                    elif msg_type == "port_found":
                        port_data = data.get('data', {})
                        total = data.get('total_ports', 0)
                        stats['ports'] = total
                        print_port(f"Port {port_data.get('port')}/{port_data.get('protocol')} - "
                                 f"{port_data.get('state')} - {port_data.get('service')} "
                                 f"(Total: {total})")
                    
                    elif msg_type == "vulnerability_found":
                        vuln_data = data.get('data', {})
                        total = data.get('total_vulns', 0)
                        stats['vulnerabilities'] = total
                        print_vuln(f"{vuln_data.get('description')} (Total: {total})")
                    
                    elif msg_type == "completed":
                        results = data.get('results', {})
                        print_success(f"\nScan completed!")
                        print(f"\n{Colors.BOLD}Final Results:{Colors.RESET}")
                        print(f"  Open Ports: {Colors.GREEN}{results.get('total_open_ports', 0)}{Colors.RESET}")
                        print(f"  Vulnerabilities: {Colors.RED}{results.get('total_vulnerabilities', 0)}{Colors.RESET}")
                        print(f"  Logs Processed: {stats['logs']}")
                        break
                    
                    elif msg_type == "failed":
                        error_msg = data.get('message', 'Unknown error')
                        print_error(f"Scan failed: {error_msg}")
                        break
                    
                    elif msg_type == "error":
                        error_msg = data.get('message', 'Unknown error')
                        print_error(f"Error: {error_msg}")
                        break
                
                except asyncio.TimeoutError:
                    print_error("WebSocket timeout - scan took too long")
                    break
                except websockets.exceptions.ConnectionClosed:
                    print_info("WebSocket connection closed")
                    break
        
    except Exception as e:
        print_error(f"Error during scan: {e}")


async def realtime_nikto_scan(token: str, target_url: str):
    """Run real-time Nikto web scan"""
    print_header(f"Real-time Nikto Scan: {target_url}")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        # Start the scan
        print_info(f"Starting Nikto web vulnerability scan...")
        response = requests.post(
            f"{API_URL}/api/realtime/scan/nikto/realtime",
            headers=headers,
            params={"url": target_url}
        )
        
        if response.status_code != 200:
            print_error(f"Failed to start scan: {response.status_code} - {response.text}")
            return
        
        result = response.json()
        scan_id = result['scan_id']
        ws_url = result['websocket_url'].replace('localhost', '127.0.0.1')
        
        print_success(f"Scan started! ID: {scan_id}")
        print_info(f"Connecting to WebSocket...")
        
        # Connect to WebSocket
        async with websockets.connect(ws_url) as websocket:
            print_success("WebSocket connected! Streaming results...\n")
            
            findings_count = 0
            
            while True:
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=300.0)
                    data = json.loads(message)
                    
                    msg_type = data.get('type')
                    
                    if msg_type == "status":
                        print(f"{Colors.CYAN}[STATUS]{Colors.RESET} {data.get('message')}")
                    
                    elif msg_type == "log":
                        log_msg = data.get('message', '')
                        # Only show Nikto findings
                        if log_msg.startswith('+'):
                            print(f"{Colors.YELLOW}[FINDING]{Colors.RESET} {log_msg}")
                    
                    elif msg_type == "finding":
                        finding = data.get('data', {})
                        total = data.get('total_findings', 0)
                        findings_count = total
                        print(f"{Colors.MAGENTA}🔍 [{finding.get('severity', 'INFO').upper()}]{Colors.RESET} "
                              f"{finding.get('path', '')} - {finding.get('description', '')} "
                              f"(Total: {total})")
                    
                    elif msg_type == "completed":
                        results = data.get('results', {})
                        print_success(f"\nNikto scan completed!")
                        print(f"\n{Colors.BOLD}Final Results:{Colors.RESET}")
                        print(f"  Total Findings: {Colors.YELLOW}{results.get('total_findings', 0)}{Colors.RESET}")
                        print(f"  Vulnerabilities: {Colors.RED}{results.get('total_vulnerabilities', 0)}{Colors.RESET}")
                        break
                    
                    elif msg_type == "failed":
                        print_error(f"Scan failed: {data.get('message')}")
                        break
                    
                    elif msg_type == "error":
                        print_error(f"Error: {data.get('message')}")
                        break
                
                except asyncio.TimeoutError:
                    print_error("WebSocket timeout")
                    break
                except websockets.exceptions.ConnectionClosed:
                    print_info("WebSocket connection closed")
                    break
        
    except Exception as e:
        print_error(f"Error during scan: {e}")


async def main():
    print_header("CyberShield AI - Real-time VAPT Scanner")
    print(f"Target: {Colors.BOLD}{TEST_TARGET}{Colors.RESET}")
    print(f"API URL: {Colors.BOLD}{API_URL}{Colors.RESET}")
    print(f"Time: {Colors.BOLD}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
    
    # Get authentication
    token = get_auth_token()
    if not token:
        print_error("Failed to authenticate")
        return
    
    print_success("Authenticated successfully\n")
    
    # Menu
    print("Select scan type:")
    print("1. Real-time Nmap Port Scan (Quick)")
    print("2. Real-time Nmap Vulnerability Scan")
    print("3. Real-time Nikto Web Scan")
    print("4. Run All Scans")
    
    choice = input("\nEnter choice (1-4): ").strip()
    
    if choice == "1":
        await realtime_nmap_scan(token, TEST_TARGET, "quick")
    elif choice == "2":
        await realtime_nmap_scan(token, TEST_TARGET, "vuln")
    elif choice == "3":
        await realtime_nikto_scan(token, f"http://{TEST_TARGET}/")
    elif choice == "4":
        await realtime_nmap_scan(token, TEST_TARGET, "quick")
        await realtime_nikto_scan(token, f"http://{TEST_TARGET}/")
    else:
        print_error("Invalid choice")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print_info("\n\nScan cancelled by user")
    except Exception as e:
        print_error(f"Error: {e}")
