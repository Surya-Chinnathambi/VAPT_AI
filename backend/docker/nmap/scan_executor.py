#!/usr/bin/env python3
"""
Nmap Scan Executor - Runs inside Docker container
Enforces timeout, validates input, executes nmap safely
"""
import sys
import os
import subprocess
import json
import argparse
import signal
import re
from typing import List, Dict, Optional


class ScanTimeout(Exception):
    """Raised when scan exceeds maximum time"""
    pass


def timeout_handler(signum, frame):
    """Signal handler for scan timeout"""
    raise ScanTimeout("Scan exceeded maximum allowed time")


def validate_target(target: str) -> bool:
    """
    Validate scan target to prevent command injection
    
    Args:
        target: IP address or hostname to scan
        
    Returns:
        True if valid, raises ValueError if invalid
    """
    # IP address pattern (IPv4)
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
    
    # Hostname pattern (basic validation)
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    
    if re.match(ip_pattern, target) or re.match(hostname_pattern, target):
        # Additional checks for dangerous characters
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '\n', '\r']
        if any(char in target for char in dangerous_chars):
            raise ValueError(f"Invalid characters detected in target: {target}")
        return True
    
    raise ValueError(f"Invalid target format: {target}")


def validate_ports(ports: str) -> bool:
    """
    Validate port specification
    
    Args:
        ports: Port specification (e.g., "80,443", "1-1000")
        
    Returns:
        True if valid, raises ValueError if invalid
    """
    # Allow port ranges, comma-separated ports, or single ports
    port_pattern = r'^[\d,\-]+$'
    
    if re.match(port_pattern, ports):
        # Check for command injection attempts
        if any(char in ports for char in [';', '&', '|', '`', '$', '(', ')']):
            raise ValueError(f"Invalid characters in port specification: {ports}")
        return True
    
    raise ValueError(f"Invalid port specification: {ports}")


def build_nmap_command(target: str, ports: Optional[str] = None, scan_type: str = "basic") -> List[str]:
    """
    Build safe nmap command with validated parameters
    
    Args:
        target: Validated target IP/hostname
        ports: Port specification (default: common ports)
        scan_type: Type of scan (basic, stealth, aggressive)
        
    Returns:
        List of command arguments for subprocess
    """
    # Base command
    cmd = ["nmap"]
    
    # Scan type configuration
    if scan_type == "stealth":
        cmd.extend(["-sS", "-T2"])  # SYN scan, polite timing
    elif scan_type == "aggressive":
        cmd.extend(["-A", "-T4"])  # OS detection, version detection, aggressive timing
    else:  # basic
        cmd.extend(["-sT", "-T3"])  # TCP connect, normal timing
    
    # Port specification
    if ports:
        validate_ports(ports)
        cmd.extend(["-p", ports])
    else:
        cmd.append("-F")  # Fast scan (top 100 ports)
    
    # Output format
    cmd.extend(["-oX", "-"])  # XML output to stdout
    cmd.append("--privileged")  # Use privileged mode (container has limited caps)
    
    # Add target (already validated)
    cmd.append(target)
    
    return cmd


def parse_nmap_xml(xml_output: str) -> Dict:
    """
    Parse nmap XML output into JSON structure
    
    Args:
        xml_output: XML output from nmap
        
    Returns:
        Dictionary with scan results
    """
    # For now, return raw XML (can be enhanced with XML parsing library)
    # In production, use xml.etree.ElementTree for proper parsing
    return {
        "raw_xml": xml_output,
        "format": "nmap_xml",
        "scan_completed": True
    }


def execute_scan(target: str, ports: Optional[str] = None, scan_type: str = "basic", timeout: int = 300) -> Dict:
    """
    Execute nmap scan with security controls
    
    Args:
        target: Target to scan
        ports: Port specification
        scan_type: Type of scan
        timeout: Maximum execution time in seconds
        
    Returns:
        Dictionary with scan results
    """
    # Validate input
    validate_target(target)
    
    # Set up timeout handler
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)
    
    try:
        # Build command
        cmd = build_nmap_command(target, ports, scan_type)
        
        # Execute nmap
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False  # Don't raise on non-zero exit
        )
        
        # Cancel timeout
        signal.alarm(0)
        
        # Parse results
        if result.returncode == 0:
            scan_results = parse_nmap_xml(result.stdout)
            scan_results["success"] = True
            scan_results["error"] = None
        else:
            scan_results = {
                "success": False,
                "error": result.stderr,
                "raw_output": result.stdout
            }
        
        return scan_results
        
    except ScanTimeout:
        signal.alarm(0)
        return {
            "success": False,
            "error": f"Scan timed out after {timeout} seconds",
            "timeout": True
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"Scan exceeded timeout ({timeout}s)",
            "timeout": True
        }
    except Exception as e:
        signal.alarm(0)
        return {
            "success": False,
            "error": f"Scan execution failed: {str(e)}"
        }


def main():
    """Main entry point for scan executor"""
    parser = argparse.ArgumentParser(description="Nmap Scan Executor (Containerized)")
    parser.add_argument("--target", required=True, help="Target IP address or hostname")
    parser.add_argument("--ports", help="Port specification (e.g., 80,443 or 1-1000)")
    parser.add_argument("--scan-type", choices=["basic", "stealth", "aggressive"], default="basic",
                        help="Type of scan to perform")
    parser.add_argument("--timeout", type=int, default=300, help="Maximum scan time in seconds")
    parser.add_argument("--output", help="Output file path (default: stdout)")
    
    args = parser.parse_args()
    
    # Get timeout from environment if not specified
    max_timeout = int(os.getenv("MAX_SCAN_TIME", "300"))
    timeout = min(args.timeout, max_timeout)
    
    # Execute scan
    results = execute_scan(args.target, args.ports, args.scan_type, timeout)
    
    # Output results
    output_json = json.dumps(results, indent=2)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output_json)
    else:
        print(output_json)
    
    # Exit with appropriate code
    sys.exit(0 if results.get("success") else 1)


if __name__ == "__main__":
    main()
