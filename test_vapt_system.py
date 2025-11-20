"""
Test AI-Powered VAPT System with Real-Time WebSocket Streaming
Tests the complete VAPT orchestration with http://testphp.vulnweb.com/
"""
import requests
import websocket
import json
import time
import threading
from colorama import init, Fore, Style

init()

BASE_URL = "http://localhost:8000"
API_URL = f"{BASE_URL}/api"

def print_header(text):
    """Print formatted header"""
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{text.center(70)}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")

def print_success(text):
    """Print success message"""
    print(f"{Fore.GREEN}[OK] {text}{Style.RESET_ALL}")

def print_error(text):
    """Print error message"""
    print(f"{Fore.RED}[FAIL] {text}{Style.RESET_ALL}")

def print_info(text):
    """Print info message"""
    print(f"{Fore.YELLOW}[INFO] {text}{Style.RESET_ALL}")

def print_vapt_update(data):
    """Print VAPT progress update"""
    update_type = data.get("type", "unknown")
    
    if update_type == "scan_started":
        print_info(f"VAPT Scan Started: {data.get('message')}")
    
    elif update_type == "plan_generated":
        plan = data.get("plan", {})
        print_success(f"AI Testing Plan: {len(plan.get('phases', []))} phases")
        for phase in plan.get("phases", []):
            print(f"  - {phase.get('phase')}: {len(phase.get('tools', []))} tools")
    
    elif update_type == "phase_started":
        print_info(f"Phase: {data.get('phase')} [{data.get('tools', 0)} tools]")
    
    elif update_type == "tool_started":
        print(f"  {Fore.BLUE}→{Style.RESET_ALL} Running: {data.get('tool')}")
    
    elif update_type == "tool_completed":
        findings = data.get("findings", 0)
        if findings > 0:
            print(f"  {Fore.RED}✓{Style.RESET_ALL} {data.get('tool')}: {findings} findings")
        else:
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {data.get('tool')}: Clean")
    
    elif update_type == "phase_completed":
        phase = data.get("phase")
        findings = data.get("findings", 0)
        risk_score = data.get("risk_score", 0)
        print_success(f"Phase Complete: {phase} | Findings: {findings} | Risk: {risk_score}/10")
    
    elif update_type == "scan_completed":
        summary = data.get("executive_summary", {})
        print_header("VAPT SCAN COMPLETE")
        print(f"{Fore.YELLOW}Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}{Style.RESET_ALL}")
        print(f"{Fore.RED}Critical Issues: {summary.get('critical_issues', 0)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Risk Score: {summary.get('overall_risk_score', 0)}/10{Style.RESET_ALL}")
    
    elif update_type == "scan_failed":
        print_error(f"Scan Failed: {data.get('error')}")
    
    elif update_type != "heartbeat":
        print_info(f"{update_type}: {data.get('message', '')}")

def authenticate():
    """Authenticate and get token"""
    print_header("Authentication")
    
    credentials = {
        "username": "scantest2",
        "password": "Test123!"
    }
    
    response = requests.post(f"{API_URL}/auth/login", json=credentials)
    
    if response.status_code == 200:
        token = response.json()["access_token"]
        print_success(f"Authenticated as: {credentials['username']}")
        return token
    else:
        print_error(f"Authentication failed: {response.status_code}")
        print(response.text)
        return None

def list_available_tools(token):
    """List all available VAPT tools"""
    print_header("Available VAPT Tools")
    
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{API_URL}/vapt/tools", headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        print_success(f"Total Tools: {data['total_tools']}")
        print_info("AI Orchestrated: Yes | Parallel Execution: Yes\n")
        
        for category, tools in data["categories"].items():
            print(f"{Fore.CYAN}{category.upper()}:{Style.RESET_ALL}")
            for tool in tools:
                print(f"  • {tool['name']}: {tool['description']}")
                print(f"    Docker: {tool['docker_image']}")
            print()
    else:
        print_error(f"Failed to list tools: {response.status_code}")

def start_vapt_scan(token, target):
    """Start AI-powered VAPT scan"""
    print_header("Starting AI-Powered VAPT Scan")
    print_info(f"Target: {target}")
    
    scan_config = {
        "target": target,
        "scope": {
            "web": True,
            "network": True
        },
        "phases": ["reconnaissance", "scanning"],
        "deep_scan": False,
        "include_exploitation": False  # Safety first!
    }
    
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(f"{API_URL}/vapt/start", json=scan_config, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        scan_id = data["scan_id"]
        print_success(f"VAPT Scan Initiated: {scan_id}")
        print_info(f"Estimated Duration: {data['estimated_duration']}")
        return scan_id
    else:
        print_error(f"Failed to start scan: {response.status_code}")
        print(response.text)
        return None

def stream_vapt_progress(scan_id, token):
    """Stream real-time VAPT progress via WebSocket"""
    print_header("Real-Time VAPT Progress Stream")
    
    ws_url = f"ws://localhost:8000/api/vapt/stream/{scan_id}"
    
    def on_message(ws, message):
        try:
            data = json.loads(message)
            print_vapt_update(data)
        except Exception as e:
            print_error(f"Error processing message: {e}")
    
    def on_error(ws, error):
        print_error(f"WebSocket error: {error}")
    
    def on_close(ws, close_status_code, close_msg):
        print_info("WebSocket connection closed")
    
    def on_open(ws):
        print_success("WebSocket connected - streaming live updates")
    
    ws = websocket.WebSocketApp(
        ws_url,
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close
    )
    
    # Run WebSocket in separate thread
    ws_thread = threading.Thread(target=ws.run_forever)
    ws_thread.daemon = True
    ws_thread.start()
    
    return ws, ws_thread

def get_vapt_report(scan_id, token, format="json"):
    """Get final VAPT report"""
    print_header(f"Retrieving VAPT Report ({format.upper()})")
    
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{API_URL}/vapt/report/{scan_id}?format={format}", headers=headers)
    
    if response.status_code == 200:
        if format == "json":
            report = response.json()
            print_success("Report Retrieved")
            
            # Display executive summary
            exec_summary = report.get("executive_summary", {})
            print(f"\n{Fore.YELLOW}Executive Summary:{Style.RESET_ALL}")
            print(f"  Overall Risk: {exec_summary.get('overall_risk_score', 0)}/10")
            print(f"  Total Vulnerabilities: {exec_summary.get('total_vulnerabilities', 0)}")
            print(f"  Critical Issues: {exec_summary.get('critical_issues', 0)}")
            
            print(f"\n{Fore.YELLOW}Top Recommendations:{Style.RESET_ALL}")
            for i, rec in enumerate(exec_summary.get('recommendations', [])[:3], 1):
                print(f"  {i}. {rec}")
            
            return report
        else:
            print_success(f"Report retrieved in {format} format")
            return response.json()
    else:
        print_error(f"Failed to get report: {response.status_code}")
        print(response.text)
        return None

def main():
    """Main test workflow"""
    print_header("AI-Powered VAPT Testing Suite")
    print(f"{Fore.CYAN}CyberShield AI - Automated Penetration Testing{Style.RESET_ALL}\n")
    
    # Step 1: Authenticate
    token = authenticate()
    if not token:
        return
    
    # Step 2: List available tools
    list_available_tools(token)
    
    # Step 3: Start VAPT scan
    target = "http://testphp.vulnweb.com"
    scan_id = start_vapt_scan(token, target)
    if not scan_id:
        return
    
    # Step 4: Stream real-time progress
    ws, ws_thread = stream_vapt_progress(scan_id, token)
    
    # Step 5: Wait for scan completion (monitor for up to 10 minutes)
    print_info("Monitoring scan progress... (this may take several minutes)")
    max_wait = 600  # 10 minutes
    start_time = time.time()
    
    while time.time() - start_time < max_wait:
        time.sleep(5)
        
        # Check if scan is complete
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(f"{API_URL}/vapt/report/{scan_id}", headers=headers)
        
        if response.status_code == 200:
            # Scan complete!
            ws.close()
            break
        elif response.status_code == 400:
            # Still running
            continue
        else:
            print_error(f"Unexpected response: {response.status_code}")
            break
    
    # Step 6: Get final report
    time.sleep(2)  # Small delay to ensure DB is updated
    report = get_vapt_report(scan_id, token, format="json")
    
    if report:
        # Also get markdown report
        print("\n")
        md_report = get_vapt_report(scan_id, token, format="markdown")
        
        if md_report:
            # Save markdown to file
            with open(f"vapt_report_{scan_id}.md", "w") as f:
                f.write(md_report["markdown"])
            print_success(f"Markdown report saved: vapt_report_{scan_id}.md")
    
    print_header("Test Complete")
    print_success("AI-Powered VAPT test completed successfully!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
    except Exception as e:
        print_error(f"Test failed: {e}")
        import traceback
        traceback.print_exc()
