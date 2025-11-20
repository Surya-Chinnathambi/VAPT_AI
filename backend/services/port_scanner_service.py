import socket
import os
import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import List, Optional, Dict

logger = logging.getLogger(__name__)

# Check if Docker is available
DOCKER_AVAILABLE = os.getenv("USE_DOCKER_SCANS", "true").lower() == "true"

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MS-RPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
    995: "POP3S", 1723: "PPTP", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
}

def scan_port(host: str, port: int, timeout: int = 3) -> Dict:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                except:
                    banner = ""
                return {
                    'port': port,
                    'status': 'open',
                    'service': COMMON_PORTS.get(port, 'Unknown'),
                    'banner': banner.strip()
                }
    except Exception:
        pass
    
    return {
        'port': port,
        'status': 'closed',
        'service': COMMON_PORTS.get(port, 'Unknown'),
        'banner': ''
    }

async def perform_port_scan_docker(host: str, ports: Optional[List[int]] = None, scan_type: str = "common") -> Dict:
    """
    Perform port scan using Docker container (Week 5-6 Implementation)
    
    Args:
        host: Target hostname or IP
        ports: List of ports to scan (optional)
        scan_type: Type of scan (common, stealth, aggressive)
        
    Returns:
        Dictionary with scan results
    """
    try:
        from core.docker_manager import get_docker_manager
        
        docker_manager = get_docker_manager()
        
        # Convert port list to string specification
        if ports:
            port_spec = ','.join(str(p) for p in ports)
        else:
            # Use default ports based on scan type
            if scan_type == "common":
                port_spec = ','.join(str(p) for p in COMMON_PORTS.keys())
            elif scan_type == "top1000":
                port_spec = "1-1000"
            else:
                port_spec = None
        
        # Map scan_type to nmap scan type
        nmap_scan_type = "basic"
        if scan_type in ["stealth", "aggressive"]:
            nmap_scan_type = scan_type
        
        # Execute scan in Docker container
        logger.info(f"Starting Docker-based port scan: host={host}, type={nmap_scan_type}")
        results = await docker_manager.run_nmap_scan(
            target=host,
            ports=port_spec,
            scan_type=nmap_scan_type,
            timeout=300
        )
        
        # Format results to match expected structure
        if results.get('success'):
            return {
                'host': host,
                'scan_time': datetime.now().isoformat(),
                'scan_method': 'docker_nmap',
                'raw_results': results,
                'open_ports': [],  # Parse from nmap XML in production
                'closed_ports': [],
                'total_scanned': len(ports) if ports else 0
            }
        else:
            # Fallback to native scan on error
            logger.warning(f"Docker scan failed, falling back to native: {results.get('error')}")
            return perform_port_scan_native(host, ports, scan_type)
            
    except Exception as e:
        logger.error(f"Docker scan error: {e}, falling back to native scan")
        return perform_port_scan_native(host, ports, scan_type)


def perform_port_scan_native(host: str, ports: Optional[List[int]] = None, scan_type: str = "common") -> Dict:
    """
    Perform port scan using native Python (fallback method)
    
    Args:
        host: Target hostname or IP
        ports: List of ports to scan
        scan_type: Type of scan
        
    Returns:
        Dictionary with scan results
    """
    if ports is None:
        if scan_type == "common":
            ports = list(COMMON_PORTS.keys())
        elif scan_type == "top1000":
            ports = list(range(1, 1001))
        else:
            ports = list(COMMON_PORTS.keys())
    
    results = {
        'host': host,
        'scan_time': datetime.now().isoformat(),
        'scan_method': 'native_python',
        'open_ports': [],
        'closed_ports': [],
        'total_scanned': len(ports)
    }
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        scan_results = executor.map(lambda p: scan_port(host, p), ports)
    
    for result in scan_results:
        if result['status'] == 'open':
            results['open_ports'].append(result)
        else:
            results['closed_ports'].append(result)
    
    return results


def perform_port_scan(host: str, ports: Optional[List[int]] = None, scan_type: str = "common") -> Dict:
    """
    Perform port scan (auto-selects Docker or native based on configuration)
    
    Args:
        host: Target hostname or IP
        ports: List of ports to scan
        scan_type: Type of scan (common, top1000, stealth, aggressive)
        
    Returns:
        Dictionary with scan results
    """
    if DOCKER_AVAILABLE:
        try:
            # Run async Docker scan
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(perform_port_scan_docker(host, ports, scan_type))
                return result
            finally:
                loop.close()
        except Exception as e:
            logger.error(f"Docker scan failed: {e}")
            return perform_port_scan_native(host, ports, scan_type)
    else:
        logger.info("Docker scans disabled, using native scan")
        return perform_port_scan_native(host, ports, scan_type)
