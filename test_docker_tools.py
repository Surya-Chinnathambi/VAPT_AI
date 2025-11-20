"""
Test Docker VAPT Tools Integration
Tests each security tool's Docker execution
"""
import asyncio
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from core.docker_manager import get_docker_manager
from colorama import init, Fore, Style

init()

async def test_nmap_scan():
    """Test Nmap Docker execution"""
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Testing Nmap Docker Tool{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    
    try:
        dm = get_docker_manager()
        print(f"{Fore.YELLOW}[INFO] Running Nmap scan on scanme.nmap.org...{Style.RESET_ALL}")
        
        result = await dm.run_nmap_scan(
            target="scanme.nmap.org",
            ports="80,443",
            scan_type="basic",
            timeout=60
        )
        
        if result.get("success"):
            print(f"{Fore.GREEN}[OK] Nmap scan completed{Style.RESET_ALL}")
            print(f"  Open ports: {len(result.get('open_ports', []))}")
            for port in result.get('open_ports', [])[:3]:
                print(f"    - Port {port['port']}: {port.get('service', 'unknown')}")
            return True
        else:
            print(f"{Fore.RED}[FAIL] Nmap scan failed: {result.get('error')}{Style.RESET_ALL}")
            return False
            
    except Exception as e:
        print(f"{Fore.RED}[FAIL] Nmap test error: {e}{Style.RESET_ALL}")
        return False

async def test_generic_tool_nuclei():
    """Test Nuclei via generic tool runner"""
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Testing Nuclei (Generic Tool Runner){Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    
    try:
        dm = get_docker_manager()
        print(f"{Fore.YELLOW}[INFO] Running Nuclei version check...{Style.RESET_ALL}")
        
        result = await dm.run_generic_tool(
            image="projectdiscovery/nuclei:latest",
            command="nuclei -version",
            timeout=30
        )
        
        if result.get("success"):
            print(f"{Fore.GREEN}[OK] Nuclei tool available{Style.RESET_ALL}")
            print(f"  Output: {result.get('output', '').strip()[:100]}")
            return True
        else:
            print(f"{Fore.RED}[FAIL] Nuclei test failed: {result.get('error')}{Style.RESET_ALL}")
            return False
            
    except Exception as e:
        print(f"{Fore.RED}[FAIL] Nuclei test error: {e}{Style.RESET_ALL}")
        return False

async def test_generic_tool_trivy():
    """Test Trivy container scanner"""
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Testing Trivy Container Scanner{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    
    try:
        dm = get_docker_manager()
        print(f"{Fore.YELLOW}[INFO] Running Trivy version check...{Style.RESET_ALL}")
        
        result = await dm.run_generic_tool(
            image="aquasec/trivy:latest",
            command="trivy -v",
            timeout=30
        )
        
        if result.get("success"):
            print(f"{Fore.GREEN}[OK] Trivy tool available{Style.RESET_ALL}")
            print(f"  Output: {result.get('output', '').strip()[:100]}")
            return True
        else:
            print(f"{Fore.RED}[FAIL] Trivy test failed: {result.get('error')}{Style.RESET_ALL}")
            return False
            
    except Exception as e:
        print(f"{Fore.RED}[FAIL] Trivy test error: {e}{Style.RESET_ALL}")
        return False

async def test_docker_pull_tools():
    """Pre-pull common security tools"""
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Pre-pulling Security Tool Images{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    
    tools = [
        ("projectdiscovery/nuclei:latest", "Nuclei - Template scanner"),
        ("aquasec/trivy:latest", "Trivy - Container scanner"),
        ("frapsoft/nikto:latest", "Nikto - Web scanner"),
        ("instrumentisto/nmap:latest", "Nmap - Network scanner"),
    ]
    
    dm = get_docker_manager()
    pulled = 0
    
    for image, description in tools:
        try:
            print(f"{Fore.YELLOW}[INFO] Checking {description}...{Style.RESET_ALL}", end=" ")
            dm.client.images.get(image)
            print(f"{Fore.GREEN}Already available{Style.RESET_ALL}")
            pulled += 1
        except:
            try:
                print(f"{Fore.YELLOW}Pulling...{Style.RESET_ALL}", end=" ")
                dm.client.images.pull(image)
                print(f"{Fore.GREEN}Downloaded{Style.RESET_ALL}")
                pulled += 1
            except Exception as e:
                print(f"{Fore.RED}Failed: {e}{Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}[OK] {pulled}/{len(tools)} tools available{Style.RESET_ALL}")
    return pulled == len(tools)

async def test_docker_stats():
    """Show Docker container statistics"""
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Docker Container Statistics{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    
    try:
        dm = get_docker_manager()
        stats = dm.get_container_stats()
        
        print(f"Total scan containers: {stats.get('total_containers', 0)}")
        print(f"Running: {stats.get('running', 0)}")
        print(f"Stopped: {stats.get('exited', 0)}")
        
        if stats.get('containers'):
            print(f"\nRecent containers:")
            for container in stats['containers'][:5]:
                print(f"  - {container['name']}: {container['status']} ({container['image']})")
        
        return True
        
    except Exception as e:
        print(f"{Fore.RED}[FAIL] Stats error: {e}{Style.RESET_ALL}")
        return False

async def main():
    """Run all Docker tool tests"""
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Docker VAPT Tools Integration Test Suite{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    
    results = {}
    
    # Test 1: Pull tools
    results['pull_tools'] = await test_docker_pull_tools()
    
    # Test 2: Nmap
    results['nmap'] = await test_nmap_scan()
    
    # Test 3: Nuclei
    results['nuclei'] = await test_generic_tool_nuclei()
    
    # Test 4: Trivy
    results['trivy'] = await test_generic_tool_trivy()
    
    # Test 5: Stats
    results['stats'] = await test_docker_stats()
    
    # Summary
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Test Summary{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        status = f"{Fore.GREEN}PASS{Style.RESET_ALL}" if result else f"{Fore.RED}FAIL{Style.RESET_ALL}"
        print(f"  {test_name}: {status}")
    
    success_rate = (passed / total * 100) if total > 0 else 0
    print(f"\n{Fore.YELLOW}Success Rate: {success_rate:.1f}% ({passed}/{total}){Style.RESET_ALL}")
    
    if success_rate >= 80:
        print(f"{Fore.GREEN}\n✓ Docker VAPT tools are ready!{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}\n✗ Some Docker tools need attention{Style.RESET_ALL}")

if __name__ == "__main__":
    asyncio.run(main())
