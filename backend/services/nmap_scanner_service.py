"""
Advanced Nmap Scanner Service
Real-time vulnerability scanning with Nmap
"""
import subprocess
import json
import xml.etree.ElementTree as ET
from typing import List, Optional, Dict
from datetime import datetime
import re

class NmapScanner:
    def __init__(self):
        self.nmap_available = self.check_nmap_installed()
    
    def check_nmap_installed(self) -> bool:
        """Check if Nmap is installed"""
        try:
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def install_nmap_instructions(self) -> str:
        """Return instructions for installing Nmap"""
        return """
        Nmap Installation:
        
        Windows: 
          1. Download from https://nmap.org/download.html
          2. Run installer and add to PATH
          
        Linux:
          sudo apt-get install nmap (Debian/Ubuntu)
          sudo yum install nmap (RedHat/CentOS)
          
        macOS:
          brew install nmap
        """
    
    def quick_scan(self, target: str) -> Dict:
        """Quick scan - top 100 ports"""
        if not self.nmap_available:
            return self._fallback_scan(target, scan_type="quick")
        
        try:
            cmd = [
                'nmap',
                '-F',  # Fast scan (100 most common ports)
                '--open',  # Only show open ports
                '-T4',  # Aggressive timing
                '-oX', '-',  # XML output to stdout
                target
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return self._parse_nmap_xml(result.stdout, scan_type="quick")
        except Exception as e:
            return self._fallback_scan(target, scan_type="quick")
    
    def full_scan(self, target: str) -> Dict:
        """Comprehensive scan - all ports"""
        if not self.nmap_available:
            return self._fallback_scan(target, scan_type="full")
        
        try:
            cmd = [
                'nmap',
                '-p-',  # All ports (1-65535)
                '-sV',  # Service version detection
                '-sC',  # Default NSE scripts
                '--open',
                '-T4',
                '-oX', '-',
                target
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            return self._parse_nmap_xml(result.stdout, scan_type="full")
        except Exception as e:
            return self._fallback_scan(target, scan_type="full")
    
    def vulnerability_scan(self, target: str) -> Dict:
        """Vulnerability detection scan"""
        if not self.nmap_available:
            return self._fallback_scan(target, scan_type="vuln")
        
        try:
            cmd = [
                'nmap',
                '-sV',  # Version detection
                '--script=vuln',  # Vulnerability scripts
                '-T4',
                '-oX', '-',
                target
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return self._parse_nmap_xml(result.stdout, scan_type="vuln")
        except Exception as e:
            return self._fallback_scan(target, scan_type="vuln")
    
    def web_scan(self, target: str) -> Dict:
        """Web application scan"""
        if not self.nmap_available:
            return self._fallback_scan(target, scan_type="web")
        
        try:
            cmd = [
                'nmap',
                '-p80,443,8080,8443',
                '-sV',
                '--script=http-enum,http-headers,http-methods,http-robots.txt,http-title',
                '-T4',
                '-oX', '-',
                target
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            return self._parse_nmap_xml(result.stdout, scan_type="web")
        except Exception as e:
            return self._fallback_scan(target, scan_type="web")
    
    def stealth_scan(self, target: str) -> Dict:
        """Stealth SYN scan"""
        if not self.nmap_available:
            return self._fallback_scan(target, scan_type="stealth")
        
        try:
            cmd = [
                'nmap',
                '-sS',  # SYN scan
                '-Pn',  # Skip ping
                '-T2',  # Polite timing
                '--open',
                '-oX', '-',
                target
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return self._parse_nmap_xml(result.stdout, scan_type="stealth")
        except Exception as e:
            return self._fallback_scan(target, scan_type="stealth")
    
    def aggressive_scan(self, target: str) -> Dict:
        """Aggressive scan with OS detection"""
        if not self.nmap_available:
            return self._fallback_scan(target, scan_type="aggressive")
        
        try:
            cmd = [
                'nmap',
                '-A',  # Aggressive: OS detection, version detection, script scanning, traceroute
                '-T4',
                '--open',
                '-oX', '-',
                target
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return self._parse_nmap_xml(result.stdout, scan_type="aggressive")
        except Exception as e:
            return self._fallback_scan(target, scan_type="aggressive")
    
    def _parse_nmap_xml(self, xml_output: str, scan_type: str) -> Dict:
        """Parse Nmap XML output"""
        try:
            root = ET.fromstring(xml_output)
            
            results = {
                'scan_type': scan_type,
                'timestamp': datetime.now().isoformat(),
                'nmap_version': root.get('version', 'Unknown'),
                'hosts': []
            }
            
            for host in root.findall('.//host'):
                status = host.find('status')
                if status is None or status.get('state') != 'up':
                    continue
                
                address = host.find('address')
                host_data = {
                    'ip': address.get('addr') if address is not None else 'Unknown',
                    'status': 'up',
                    'ports': [],
                    'os': [],
                    'vulnerabilities': []
                }
                
                # Parse hostnames
                hostnames = host.findall('.//hostname')
                if hostnames:
                    host_data['hostnames'] = [h.get('name') for h in hostnames]
                
                # Parse ports
                for port in host.findall('.//port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol', 'tcp')
                    
                    state = port.find('state')
                    service = port.find('service')
                    
                    port_data = {
                        'port': int(port_id),
                        'protocol': protocol,
                        'state': state.get('state') if state is not None else 'unknown',
                        'service': service.get('name') if service is not None else 'unknown',
                        'product': service.get('product', '') if service is not None else '',
                        'version': service.get('version', '') if service is not None else '',
                        'extrainfo': service.get('extrainfo', '') if service is not None else ''
                    }
                    
                    # Parse scripts (vulnerabilities, etc.)
                    scripts = port.findall('.//script')
                    if scripts:
                        port_data['scripts'] = []
                        for script in scripts:
                            script_data = {
                                'id': script.get('id'),
                                'output': script.get('output', '')
                            }
                            port_data['scripts'].append(script_data)
                            
                            # Check for vulnerabilities
                            if 'vuln' in script.get('id', '').lower():
                                host_data['vulnerabilities'].append({
                                    'port': int(port_id),
                                    'script': script.get('id'),
                                    'details': script.get('output', '')
                                })
                    
                    host_data['ports'].append(port_data)
                
                # Parse OS detection
                os_matches = host.findall('.//osmatch')
                for os_match in os_matches:
                    host_data['os'].append({
                        'name': os_match.get('name'),
                        'accuracy': os_match.get('accuracy')
                    })
                
                results['hosts'].append(host_data)
            
            # Add summary
            if results['hosts']:
                total_ports = sum(len(h['ports']) for h in results['hosts'])
                open_ports = sum(len([p for p in h['ports'] if p['state'] == 'open']) for h in results['hosts'])
                total_vulns = sum(len(h['vulnerabilities']) for h in results['hosts'])
                
                results['summary'] = {
                    'total_hosts': len(results['hosts']),
                    'total_ports_scanned': total_ports,
                    'open_ports': open_ports,
                    'vulnerabilities_found': total_vulns,
                    'scan_duration': 'Completed'
                }
            
            return results
            
        except Exception as e:
            return {
                'error': f'Failed to parse Nmap output: {str(e)}',
                'scan_type': scan_type,
                'timestamp': datetime.now().isoformat()
            }
    
    def _fallback_scan(self, target: str, scan_type: str) -> Dict:
        """Fallback to Python socket scanning if Nmap not available"""
        from services.port_scanner_service import perform_port_scan
        
        ports_to_scan = {
            'quick': list(range(1, 101)),
            'full': list(range(1, 1001)),
            'web': [80, 443, 8080, 8443, 8000, 3000, 5000],
            'vuln': list(range(1, 101)),
            'stealth': list(range(1, 101)),
            'aggressive': list(range(1, 201))
        }
        
        ports = ports_to_scan.get(scan_type, list(range(1, 101)))
        result = perform_port_scan(host=target, ports=ports)  # Fixed: use host parameter
        
        # Format to match Nmap output structure
        return {
            'scan_type': scan_type,
            'timestamp': datetime.now().isoformat(),
            'nmap_version': 'Python Fallback',
            'target': target,
            'hosts': [{
                'address': result.get('host', target),
                'state': 'up',
                'ports': [
                    {
                        'port': p['port'],
                        'protocol': 'tcp',
                        'state': p['status'],
                        'service': p['service'],
                        'product': '',
                        'version': '',
                        'extrainfo': p.get('banner', '')[:50]
                    }
                    for p in result.get('open_ports', [])
                ],
                'os': [],
                'vulnerabilities': []
            }],
            'summary': {
                'total_hosts': 1,
                'total_ports_scanned': result.get('total_scanned', 0),
                'open_ports': len(result.get('open_ports', [])),
                'vulnerabilities_found': 0,
                'scan_duration': 'Completed'
            },
            'note': 'Nmap not installed. Using Python socket scanner. Install Nmap for better results.'
        }

# Global scanner instance
nmap_scanner = NmapScanner()
