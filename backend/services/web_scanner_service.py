import requests
import ssl
import socket
import os
import asyncio
import logging
from urllib.parse import urljoin, urlparse
from datetime import datetime
import urllib3
from typing import Dict

logger = logging.getLogger(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Check if Docker is available
DOCKER_AVAILABLE = os.getenv("USE_DOCKER_SCANS", "true").lower() == "true"

VULN_PATHS = [
    '/admin', '/admin.php', '/administrator', '/phpmyadmin',
    '/wp-admin', '/wp-login.php', '/login', '/robots.txt',
    '/.htaccess', '/.env', '/config.php', '/backup',
    '/backup.sql', '/database.sql', '/.git', '/.svn',
    '/test', '/debug', '/info.php', '/phpinfo.php'
]

SECURITY_HEADERS = [
    'X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection',
    'Strict-Transport-Security', 'Content-Security-Policy',
    'Referrer-Policy', 'Permissions-Policy'
]

def check_ssl_certificate(hostname: str, port: int = 443) -> Dict:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    'valid': True,
                    'subject': dict(x[0] for x in cert['subject']),
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'not_before': cert['notBefore'],
                    'not_after': cert['notAfter']
                }
    except Exception as e:
        return {'valid': False, 'error': str(e)}

def check_security_headers(url: str) -> Dict:
    try:
        response = requests.get(url, timeout=10, verify=False)
        headers_found = {}
        missing_headers = []
        
        for header in SECURITY_HEADERS:
            if header in response.headers:
                headers_found[header] = response.headers[header]
            else:
                missing_headers.append(header)
        
        return {
            'status_code': response.status_code,
            'headers_found': headers_found,
            'missing_headers': missing_headers
        }
    except Exception as e:
        return {'error': str(e)}

def check_common_vulnerabilities(base_url: str) -> list:
    findings = []
    
    for path in VULN_PATHS:
        try:
            url = urljoin(base_url, path)
            response = requests.get(url, timeout=5, verify=False, allow_redirects=False)
            
            if response.status_code == 200:
                risk = 'High' if any(x in path for x in ['.env', 'config', 'backup', '.git']) else 'Medium'
                findings.append({
                    'path': path,
                    'url': url,
                    'status_code': response.status_code,
                    'risk': risk
                })
        except:
            continue
    
    return findings

async def perform_web_scan_docker(url: str, options: Dict[str, bool]) -> Dict:
    """
    Perform web scan using Docker container (Week 5-6 Implementation)
    
    Args:
        url: Target URL
        options: Scan options (scan_ssl, scan_headers, scan_paths)
        
    Returns:
        Dictionary with scan results
    """
    try:
        from core.docker_manager import get_docker_manager
        
        docker_manager = get_docker_manager()
        
        # Determine scan type based on options
        scan_type = "full" if options.get('scan_paths', True) else "basic"
        ssl_check = options.get('scan_ssl', True)
        
        # Execute Nikto scan in Docker container
        logger.info(f"Starting Docker-based web scan: url={url}, type={scan_type}")
        nikto_results = await docker_manager.run_nikto_scan(
            url=url,
            scan_type=scan_type,
            ssl_check=ssl_check,
            timeout=600
        )
        
        # Combine with native checks (headers, SSL)
        results = {
            'url': url,
            'scan_time': datetime.now().isoformat(),
            'scan_method': 'docker_nikto',
            'ssl_info': {},
            'security_headers': {},
            'vulnerability_paths': [],
            'nikto_findings': nikto_results.get('vulnerabilities', []),
            'findings_count': nikto_results.get('findings_count', 0),
            'risk_summary': {'high': 0, 'medium': 0, 'low': 0}
        }
        
        parsed_url = urlparse(url)
        
        # Still use native checks for SSL and headers (faster, no need for Docker)
        if parsed_url.scheme == 'https' and options.get('scan_ssl', True):
            results['ssl_info'] = check_ssl_certificate(parsed_url.hostname)
        
        if options.get('scan_headers', True):
            results['security_headers'] = check_security_headers(url)
        
        # Calculate risk summary
        if not results['ssl_info'].get('valid', True):
            results['risk_summary']['high'] += 1
        
        missing_count = len(results['security_headers'].get('missing_headers', []))
        if missing_count > 5:
            results['risk_summary']['high'] += 1
        elif missing_count > 2:
            results['risk_summary']['medium'] += 1
        
        # Add Nikto findings to risk summary
        results['risk_summary']['medium'] += results['findings_count']
        
        return results
        
    except Exception as e:
        logger.error(f"Docker web scan error: {e}, falling back to native scan")
        return perform_web_scan_native(url, options)


def perform_web_scan_native(url: str, options: Dict[str, bool]) -> Dict:
    """
    Perform web scan using native Python (fallback method)
    
    Args:
        url: Target URL
        options: Scan options
        
    Returns:
        Dictionary with scan results
    """
    results = {
        'url': url,
        'scan_time': datetime.now().isoformat(),
        'scan_method': 'native_python',
        'ssl_info': {},
        'security_headers': {},
        'vulnerability_paths': [],
        'risk_summary': {'high': 0, 'medium': 0, 'low': 0}
    }
    
    parsed_url = urlparse(url)
    
    if parsed_url.scheme == 'https' and options.get('scan_ssl', True):
        results['ssl_info'] = check_ssl_certificate(parsed_url.hostname)
    
    if options.get('scan_headers', True):
        results['security_headers'] = check_security_headers(url)
    
    if options.get('scan_paths', True):
        results['vulnerability_paths'] = check_common_vulnerabilities(url)
    
    if not results['ssl_info'].get('valid', True):
        results['risk_summary']['high'] += 1
    
    missing_count = len(results['security_headers'].get('missing_headers', []))
    if missing_count > 5:
        results['risk_summary']['high'] += 1
    elif missing_count > 2:
        results['risk_summary']['medium'] += 1
    
    for vuln in results['vulnerability_paths']:
        risk_level = vuln.get('risk', 'Low').lower()
        results['risk_summary'][risk_level] += 1
    
    return results


def perform_web_scan(url: str, options: Dict[str, bool]) -> Dict:
    """
    Perform web vulnerability scan (auto-selects Docker or native)
    
    Args:
        url: Target URL
        options: Scan options (scan_ssl, scan_headers, scan_paths)
        
    Returns:
        Dictionary with scan results
    """
    if DOCKER_AVAILABLE:
        try:
            # Run async Docker scan
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(perform_web_scan_docker(url, options))
                return result
            finally:
                loop.close()
        except Exception as e:
            logger.error(f"Docker web scan failed: {e}")
            return perform_web_scan_native(url, options)
    else:
        logger.info("Docker scans disabled, using native scan")
        return perform_web_scan_native(url, options)
