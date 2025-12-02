"""
Kali Linux Tools Executor
Executes penetration testing tools from Kali container with AI integration
"""
import asyncio
import logging
import os
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
import docker

logger = logging.getLogger(__name__)


class KaliToolsExecutor:
    """
    Execute Kali Linux penetration testing tools via Docker
    Provides 100+ security tools for comprehensive VAPT
    """
    
    def __init__(self):
        self.kali_container_name = os.getenv("KALI_CONTAINER", "cybersec_kali")
        try:
            self.docker_client = docker.from_env()
            self.kali_container = self.docker_client.containers.get(self.kali_container_name)
            logger.info(f"✅ Kali Linux container connected: {self.kali_container_name}")
        except Exception as e:
            logger.error(f"❌ Kali container not available: {e}")
            self.docker_client = None
            self.kali_container = None
    
    # ==================== RECONNAISSANCE TOOLS ====================
    
    async def nmap_scan(
        self,
        target: str,
        scan_type: str = "standard",
        ports: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Nmap - Network scanning and service detection
        Scan types: quick, standard, full, aggressive, stealth
        """
        scan_commands = {
            'quick': f'nmap -F {target}',
            'standard': f'nmap -sV {target}',
            'full': f'nmap -p- -sV -sC {target}',
            'aggressive': f'nmap -A -T4 {target}',
            'stealth': f'nmap -sS -T2 {target}',
            'vuln': f'nmap -sV --script vuln {target}'
        }
        
        command = scan_commands.get(scan_type, scan_commands['standard'])
        if ports:
            command += f' -p {ports}'
        
        return await self._execute_command(command, tool_name="nmap", target=target)
    
    async def masscan_scan(self, target: str, ports: str = "1-65535") -> Dict[str, Any]:
        """Masscan - Ultra-fast port scanner (faster than nmap)"""
        command = f'masscan {target} -p{ports} --rate=10000'
        return await self._execute_command(command, tool_name="masscan", target=target)
    
    async def subfinder_scan(self, domain: str) -> Dict[str, Any]:
        """Subfinder - Subdomain enumeration"""
        command = f'subfinder -d {domain} -silent'
        return await self._execute_command(command, tool_name="subfinder", target=domain)
    
    async def amass_enum(self, domain: str) -> Dict[str, Any]:
        """Amass - In-depth DNS enumeration and network mapping"""
        command = f'amass enum -passive -d {domain}'
        return await self._execute_command(command, tool_name="amass", target=domain)
    
    async def theharvester_scan(self, domain: str, source: str = "all") -> Dict[str, Any]:
        """TheHarvester - OSINT gathering (emails, subdomains, IPs)"""
        command = f'theHarvester -d {domain} -b {source} -l 500'
        return await self._execute_command(command, tool_name="theharvester", target=domain)
    
    async def dnsenum_scan(self, domain: str) -> Dict[str, Any]:
        """DNSenum - DNS enumeration"""
        command = f'dnsenum {domain}'
        return await self._execute_command(command, tool_name="dnsenum", target=domain)
    
    async def whatweb_scan(self, url: str) -> Dict[str, Any]:
        """WhatWeb - Web technology fingerprinting"""
        command = f'whatweb {url} -a 3'
        return await self._execute_command(command, tool_name="whatweb", target=url)
    
    # ==================== WEB APPLICATION SCANNING ====================
    
    async def nikto_scan(self, url: str, ssl: bool = True) -> Dict[str, Any]:
        """Nikto - Web server vulnerability scanner"""
        ssl_flag = '-ssl' if ssl else ''
        command = f'nikto -h {url} {ssl_flag} -Tuning 123bde'
        return await self._execute_command(command, tool_name="nikto", target=url)
    
    async def nuclei_scan(self, target: str, severity: str = "critical,high,medium") -> Dict[str, Any]:
        """Nuclei - Fast vulnerability scanner with templates"""
        command = f'nuclei -u {target} -severity {severity} -silent'
        return await self._execute_command(command, tool_name="nuclei", target=target)
    
    async def wpscan_scan(self, url: str, enumerate: str = "vp,vt,u") -> Dict[str, Any]:
        """WPScan - WordPress vulnerability scanner"""
        command = f'wpscan --url {url} --enumerate {enumerate} --random-user-agent'
        return await self._execute_command(command, tool_name="wpscan", target=url)
    
    async def sqlmap_scan(self, url: str, crawl_depth: int = 2) -> Dict[str, Any]:
        """SQLMap - Automated SQL injection detection and exploitation"""
        command = f'sqlmap -u "{url}" --batch --crawl={crawl_depth} --level=1 --risk=1'
        return await self._execute_command(command, tool_name="sqlmap", target=url)
    
    async def dirb_scan(self, url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> Dict[str, Any]:
        """DIRB - Directory/file bruteforcing"""
        command = f'dirb {url} {wordlist} -S -r'
        return await self._execute_command(command, tool_name="dirb", target=url)
    
    async def gobuster_scan(self, url: str, mode: str = "dir") -> Dict[str, Any]:
        """Gobuster - Directory/DNS/VHost bruteforcing"""
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        command = f'gobuster {mode} -u {url} -w {wordlist} -q'
        return await self._execute_command(command, tool_name="gobuster", target=url)
    
    async def ffuf_scan(self, url: str) -> Dict[str, Any]:
        """FFUF - Fast web fuzzer"""
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        command = f'ffuf -u {url}/FUZZ -w {wordlist} -mc 200,301,302 -fc 404'
        return await self._execute_command(command, tool_name="ffuf", target=url)
    
    async def wfuzz_scan(self, url: str) -> Dict[str, Any]:
        """Wfuzz - Web application bruteforcer"""
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        command = f'wfuzz -c -z file,{wordlist} --hc 404 {url}/FUZZ'
        return await self._execute_command(command, tool_name="wfuzz", target=url)
    
    async def commix_scan(self, url: str) -> Dict[str, Any]:
        """Commix - Command injection detection"""
        command = f'commix --url="{url}" --batch --crawl=2'
        return await self._execute_command(command, tool_name="commix", target=url)
    
    async def zaproxy_scan(self, target: str) -> Dict[str, Any]:
        """OWASP ZAP - Web application security scanner"""
        command = f'zap-cli quick-scan -s all -r {target}'
        return await self._execute_command(command, tool_name="zaproxy", target=target)
    
    async def wafw00f_scan(self, url: str) -> Dict[str, Any]:
        """Wafw00f - Web Application Firewall detection"""
        command = f'wafw00f {url}'
        return await self._execute_command(command, tool_name="wafw00f", target=url)
    
    # ==================== SSL/TLS SCANNING ====================
    
    async def testssl_scan(self, target: str) -> Dict[str, Any]:
        """TestSSL - SSL/TLS vulnerability scanner"""
        command = f'testssl.sh --quiet --fast {target}'
        return await self._execute_command(command, tool_name="testssl", target=target)
    
    async def sslyze_scan(self, target: str) -> Dict[str, Any]:
        """SSLyze - SSL/TLS configuration analyzer"""
        command = f'sslyze {target} --regular'
        return await self._execute_command(command, tool_name="sslyze", target=target)
    
    async def sslscan_scan(self, target: str) -> Dict[str, Any]:
        """SSLScan - SSL/TLS scanner"""
        command = f'sslscan {target}'
        return await self._execute_command(command, tool_name="sslscan", target=target)
    
    # ==================== EXPLOITATION & METASPLOIT ====================
    
    async def searchsploit_search(self, keyword: str) -> Dict[str, Any]:
        """SearchSploit - Exploit database search"""
        command = f'searchsploit {keyword} --json'
        return await self._execute_command(command, tool_name="searchsploit", target=keyword)
    
    async def msfconsole_exploit(
        self,
        exploit_path: str,
        target: str,
        payload: str = "generic/shell_reverse_tcp"
    ) -> Dict[str, Any]:
        """
        Metasploit Framework - Exploit execution
        WARNING: Only use with proper authorization!
        """
        command = f'msfconsole -q -x "use {exploit_path}; set RHOST {target}; set PAYLOAD {payload}; check; exit"'
        return await self._execute_command(command, tool_name="metasploit", target=target)
    
    # ==================== PASSWORD CRACKING ====================
    
    async def hydra_crack(
        self,
        target: str,
        service: str = "ssh",
        username: str = "admin",
        wordlist: str = "/usr/share/wordlists/rockyou.txt"
    ) -> Dict[str, Any]:
        """Hydra - Network login cracker"""
        command = f'hydra -l {username} -P {wordlist} {service}://{target} -t 4 -V'
        return await self._execute_command(command, tool_name="hydra", target=target)
    
    async def john_crack(self, hash_file: str) -> Dict[str, Any]:
        """John the Ripper - Password hash cracker"""
        command = f'john {hash_file} --format=raw-md5'
        return await self._execute_command(command, tool_name="john", target=hash_file)
    
    # ==================== WIRELESS TOOLS ====================
    
    async def aircrack_scan(self, interface: str = "wlan0") -> Dict[str, Any]:
        """Aircrack-ng - Wireless security auditing"""
        command = f'airodump-ng {interface}'
        return await self._execute_command(command, tool_name="aircrack", target=interface)
    
    # ==================== HELPER METHODS ====================
    
    async def _execute_command(
        self,
        command: str,
        tool_name: str,
        target: str,
        timeout: int = 300
    ) -> Dict[str, Any]:
        """Execute command in Kali container"""
        if not self.kali_container:
            return {
                "success": False,
                "error": "Kali Linux container not available",
                "tool": tool_name,
                "target": target
            }
        
        start_time = datetime.now()
        logger.info(f"🔧 Executing {tool_name}: {command}")
        
        try:
            # Execute command in Kali container
            exec_result = self.kali_container.exec_run(
                cmd=f'bash -c "{command}"',
                demux=True,
                stream=False
            )
            
            stdout = exec_result.output[0].decode('utf-8') if exec_result.output[0] else ""
            stderr = exec_result.output[1].decode('utf-8') if exec_result.output[1] else ""
            
            duration = (datetime.now() - start_time).total_seconds()
            
            # Parse results based on tool
            parsed_results = self._parse_tool_output(tool_name, stdout + stderr)
            
            return {
                "success": exec_result.exit_code == 0,
                "tool": tool_name,
                "target": target,
                "command": command,
                "duration": duration,
                "exit_code": exec_result.exit_code,
                "raw_output": stdout + stderr,
                "parsed_results": parsed_results,
                "findings_count": len(parsed_results.get('findings', [])),
                "timestamp": start_time.isoformat()
            }
        
        except Exception as e:
            logger.error(f"❌ {tool_name} execution failed: {e}")
            return {
                "success": False,
                "tool": tool_name,
                "target": target,
                "error": str(e),
                "duration": (datetime.now() - start_time).total_seconds()
            }
    
    def _parse_tool_output(self, tool_name: str, output: str) -> Dict[str, Any]:
        """Parse tool-specific output"""
        findings = []
        
        # Nmap parsing
        if tool_name == "nmap":
            for line in output.split('\n'):
                if '/tcp' in line or '/udp' in line:
                    findings.append({"type": "open_port", "details": line.strip()})
        
        # Nikto parsing
        elif tool_name == "nikto":
            for line in output.split('\n'):
                if line.startswith('+'):
                    findings.append({"type": "vulnerability", "details": line.strip()})
        
        # SQLMap parsing
        elif tool_name == "sqlmap":
            if "Parameter:" in output and "is vulnerable" in output:
                findings.append({"type": "sql_injection", "severity": "HIGH", "details": "SQL injection found"})
        
        # Nuclei parsing
        elif tool_name == "nuclei":
            for line in output.split('\n'):
                if '[' in line and ']' in line:
                    findings.append({"type": "template_match", "details": line.strip()})
        
        # Generic parsing
        else:
            for line in output.split('\n'):
                if any(keyword in line.lower() for keyword in ['vuln', 'exploit', 'critical', 'high', 'error']):
                    findings.append({"details": line.strip()})
        
        return {
            "findings": findings,
            "findings_count": len(findings),
            "raw_output_length": len(output)
        }
    
    def get_available_tools(self) -> Dict[str, List[str]]:
        """Get list of all available Kali tools organized by category"""
        return {
            "reconnaissance": ["nmap", "masscan", "subfinder", "amass", "theharvester", "dnsenum", "whatweb"],
            "web_scanning": ["nikto", "nuclei", "wpscan", "sqlmap", "dirb", "gobuster", "ffuf", "wfuzz", "commix", "zaproxy", "wafw00f"],
            "ssl_tls": ["testssl", "sslyze", "sslscan"],
            "exploitation": ["searchsploit", "metasploit"],
            "password": ["hydra", "john"],
            "wireless": ["aircrack"]
        }
    
    async def execute_parallel_vapt(
        self,
        target: str,
        tools: List[str],
        progress_callback: Optional[callable] = None
    ) -> Dict[str, Any]:
        """Execute multiple Kali tools in parallel for comprehensive VAPT"""
        logger.info(f"🚀 Starting parallel VAPT on {target} with {len(tools)} tools")
        
        tasks = []
        tool_methods = {
            'nmap': self.nmap_scan,
            'nikto': self.nikto_scan,
            'nuclei': self.nuclei_scan,
            'sqlmap': self.sqlmap_scan,
            'wpscan': self.wpscan_scan,
            'testssl': self.testssl_scan,
            'gobuster': self.gobuster_scan,
            'subfinder': self.subfinder_scan,
            'amass': self.amass_enum,
            'whatweb': self.whatweb_scan,
            'wafw00f': self.wafw00f_scan
        }
        
        for tool in tools:
            if tool in tool_methods:
                tasks.append(tool_methods[tool](target))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Aggregate results
        total_findings = 0
        successful_scans = 0
        
        scan_results = {}
        for i, tool in enumerate(tools):
            if i < len(results):
                result = results[i]
                if isinstance(result, dict) and result.get('success'):
                    successful_scans += 1
                    total_findings += result.get('findings_count', 0)
                scan_results[tool] = result
        
        return {
            "target": target,
            "tools_executed": len(tools),
            "successful_scans": successful_scans,
            "total_findings": total_findings,
            "scan_results": scan_results,
            "timestamp": datetime.now().isoformat()
        }


# Global instance
_kali_executor = None


def get_kali_executor() -> KaliToolsExecutor:
    """Get singleton instance of Kali tools executor"""
    global _kali_executor
    if _kali_executor is None:
        _kali_executor = KaliToolsExecutor()
    return _kali_executor
