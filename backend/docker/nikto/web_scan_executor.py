#!/usr/bin/env python3
"""
Nikto Web Scan Executor - Runs inside Docker container
Enforces timeout, validates input, executes nikto safely
"""
import sys
import os
import subprocess
import json
import argparse
import signal
import re
from typing import Dict, Optional, List
from urllib.parse import urlparse


class ScanTimeout(Exception):
    """Raised when scan exceeds maximum time"""
    pass


def timeout_handler(signum, frame):
    """Signal handler for scan timeout"""
    raise ScanTimeout("Scan exceeded maximum allowed time")


def validate_url(url: str) -> bool:
    """
    Validate target URL to prevent command injection and SSRF
    
    Args:
        url: URL to scan
        
    Returns:
        True if valid, raises ValueError if invalid
    """
    try:
        parsed = urlparse(url)
        
        # Must have scheme and netloc
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid URL format: {url}")
        
        # Only allow http/https
        if parsed.scheme not in ['http', 'https']:
            raise ValueError(f"Invalid URL scheme (must be http/https): {parsed.scheme}")
        
        # Block internal/private IP addresses (SSRF prevention)
        hostname = parsed.hostname
        if hostname:
            # Block localhost variants
            localhost_patterns = ['localhost', '127.', '0.0.0.0', '::1', '0:0:0:0:0:0:0:1']
            if any(pattern in hostname.lower() for pattern in localhost_patterns):
                raise ValueError(f"Scanning localhost is not allowed: {hostname}")
            
            # Block private IP ranges (basic check)
            if hostname.startswith(('10.', '172.16.', '192.168.')):
                raise ValueError(f"Scanning private IP addresses is not allowed: {hostname}")
        
        # Check for dangerous characters
        dangerous_chars = [';', '&', '|', '`', '$', '\n', '\r', '\x00']
        if any(char in url for char in dangerous_chars):
            raise ValueError(f"Invalid characters detected in URL: {url}")
        
        return True
        
    except Exception as e:
        raise ValueError(f"URL validation failed: {str(e)}")


def build_nikto_command(url: str, scan_type: str = "basic", ssl_check: bool = True) -> List[str]:
    """
    Build safe nikto command with validated parameters
    
    Args:
        url: Validated target URL
        scan_type: Type of scan (basic, full)
        ssl_check: Whether to check SSL certificates
        
    Returns:
        List of command arguments for subprocess
    """
    nikto_path = os.getenv("NIKTO_PATH", "/opt/nikto/program/nikto.pl")
    
    # Base command
    cmd = ["perl", nikto_path]
    
    # Target URL
    cmd.extend(["-h", url])
    
    # Output format (JSON-like)
    cmd.extend(["-Format", "txt"])
    
    # Scan type configuration
    if scan_type == "full":
        cmd.extend(["-Tuning", "123456789abc"])  # All tests
    else:  # basic
        cmd.extend(["-Tuning", "123"])  # Common tests
    
    # SSL options
    if not ssl_check:
        cmd.append("-nossl")
    
    # Disable interactive prompts
    cmd.append("-ask")
    cmd.append("no")
    
    # Set user agent
    cmd.extend(["-useragent", "CyberShieldAI-Scanner/1.0"])
    
    # Timeout per request (seconds)
    cmd.extend(["-timeout", "10"])
    
    return cmd


def parse_nikto_output(output: str) -> Dict:
    """
    Parse nikto output into structured format
    
    Args:
        output: Text output from nikto
        
    Returns:
        Dictionary with scan results
    """
    results = {
        "vulnerabilities": [],
        "server_info": {},
        "findings_count": 0
    }
    
    lines = output.split('\n')
    for line in lines:
        line = line.strip()
        
        # Extract server information
        if line.startswith('+ Server:'):
            results["server_info"]["server"] = line.replace('+ Server:', '').strip()
        
        # Extract findings (lines starting with +)
        if line.startswith('+ ') and ':' in line:
            results["vulnerabilities"].append(line[2:])  # Remove '+ ' prefix
            results["findings_count"] += 1
    
    return results


def execute_scan(url: str, scan_type: str = "basic", ssl_check: bool = True, timeout: int = 600) -> Dict:
    """
    Execute nikto scan with security controls
    
    Args:
        url: Target URL to scan
        scan_type: Type of scan (basic, full)
        ssl_check: Whether to check SSL certificates
        timeout: Maximum execution time in seconds
        
    Returns:
        Dictionary with scan results
    """
    # Validate input
    validate_url(url)
    
    # Set up timeout handler
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)
    
    try:
        # Build command
        cmd = build_nikto_command(url, scan_type, ssl_check)
        
        # Execute nikto
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        
        # Cancel timeout
        signal.alarm(0)
        
        # Parse results
        if result.returncode in [0, 1]:  # 0 = success, 1 = findings found
            parsed_results = parse_nikto_output(result.stdout)
            scan_results = {
                "success": True,
                "error": None,
                "raw_output": result.stdout,
                **parsed_results
            }
        else:
            scan_results = {
                "success": False,
                "error": result.stderr or "Nikto scan failed",
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
    """Main entry point for web scan executor"""
    parser = argparse.ArgumentParser(description="Nikto Web Scan Executor (Containerized)")
    parser.add_argument("--url", required=True, help="Target URL to scan")
    parser.add_argument("--scan-type", choices=["basic", "full"], default="basic",
                        help="Type of scan to perform")
    parser.add_argument("--no-ssl-check", action="store_true",
                        help="Disable SSL certificate verification")
    parser.add_argument("--timeout", type=int, default=600, help="Maximum scan time in seconds")
    parser.add_argument("--output", help="Output file path (default: stdout)")
    
    args = parser.parse_args()
    
    # Get timeout from environment if not specified
    max_timeout = int(os.getenv("MAX_SCAN_TIME", "600"))
    timeout = min(args.timeout, max_timeout)
    
    # Execute scan
    results = execute_scan(args.url, args.scan_type, not args.no_ssl_check, timeout)
    
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
