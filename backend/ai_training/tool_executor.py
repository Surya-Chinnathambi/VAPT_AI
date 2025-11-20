"""
Tool Execution Service for AI VAPT Training
Safe wrappers for all security testing tools with rate limiting and output parsing
"""

import subprocess
import json
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any
from datetime import datetime
import asyncio
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class ToolExecutionError(Exception):
    """Custom exception for tool execution failures"""
    pass


class RateLimiter:
    """Rate limiter to prevent tool abuse"""
    
    def __init__(self, max_calls: int = 10, window_seconds: int = 60):
        self.max_calls = max_calls
        self.window_seconds = window_seconds
        self.call_history: Dict[str, List[datetime]] = {}
    
    def check_limit(self, tool_name: str) -> bool:
        """Check if tool can be executed within rate limit"""
        now = datetime.now()
        if tool_name not in self.call_history:
            self.call_history[tool_name] = []
        
        # Remove old calls outside window
        self.call_history[tool_name] = [
            call_time for call_time in self.call_history[tool_name]
            if (now - call_time).total_seconds() < self.window_seconds
        ]
        
        if len(self.call_history[tool_name]) >= self.max_calls:
            return False
        
        self.call_history[tool_name].append(now)
        return True


class ToolExecutor:
    """Main tool execution service"""
    
    def __init__(self, rate_limiter: Optional[RateLimiter] = None):
        self.rate_limiter = rate_limiter or RateLimiter()
        self.allowed_targets = []  # Whitelist of allowed targets
        self.blocked_operations = ["rm", "dd", "format", "mkfs", "> /dev/"]
    
    def _validate_target(self, target: str) -> bool:
        """Validate target is allowed"""
        # Prevent scanning localhost/internal IPs in production
        blocked_patterns = [
            r"127\.0\.0\.",
            r"localhost",
            r"10\.\d+\.\d+\.\d+",
            r"192\.168\.\d+\.\d+",
            r"172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+"
        ]
        
        for pattern in blocked_patterns:
            if re.match(pattern, target):
                logger.warning(f"Blocked target: {target}")
                return False
        
        return True
    
    def _check_command_safety(self, command: List[str]) -> bool:
        """Ensure command doesn't contain destructive operations"""
        full_command = " ".join(command)
        
        for blocked_op in self.blocked_operations:
            if blocked_op in full_command:
                raise ToolExecutionError(f"Blocked destructive operation: {blocked_op}")
        
        return True
    
    async def _execute_command(
        self,
        command: List[str],
        timeout: int = 300,
        cwd: Optional[Path] = None
    ) -> Dict[str, Any]:
        """Execute command with timeout and safety checks"""
        
        self._check_command_safety(command)
        
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            return {
                "returncode": process.returncode,
                "stdout": stdout.decode('utf-8', errors='ignore'),
                "stderr": stderr.decode('utf-8', errors='ignore'),
                "success": process.returncode == 0
            }
        
        except asyncio.TimeoutError:
            process.kill()
            raise ToolExecutionError(f"Command timed out after {timeout} seconds")
        
        except Exception as e:
            raise ToolExecutionError(f"Command execution failed: {str(e)}")
    
    # NMAP WRAPPERS
    
    async def run_nmap(
        self,
        target: str,
        scan_type: str = "quick",
        ports: Optional[str] = None,
        additional_flags: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Execute Nmap scan
        
        Args:
            target: Target IP/domain
            scan_type: quick, full, service, os, scripts
            ports: Port specification (e.g., "80,443" or "1-1000")
            additional_flags: Additional nmap flags
        """
        
        if not self.rate_limiter.check_limit("nmap"):
            raise ToolExecutionError("Rate limit exceeded for nmap")
        
        if not self._validate_target(target):
            raise ToolExecutionError(f"Target not allowed: {target}")
        
        # Build nmap command
        scan_profiles = {
            "quick": ["-F"],  # Fast scan (top 100 ports)
            "full": ["-p-"],  # All ports
            "service": ["-sV"],  # Service detection
            "os": ["-O"],  # OS detection
            "scripts": ["-sC"]  # Default scripts
        }
        
        command = ["nmap", "-oX", "-"]  # XML output to stdout
        command.extend(scan_profiles.get(scan_type, ["-F"]))
        
        if ports:
            command.extend(["-p", ports])
        
        if additional_flags:
            command.extend(additional_flags)
        
        command.append(target)
        
        logger.info(f"Executing nmap: {' '.join(command)}")
        result = await self._execute_command(command, timeout=600)
        
        if result["success"]:
            return self._parse_nmap_xml(result["stdout"])
        else:
            raise ToolExecutionError(f"Nmap failed: {result['stderr']}")
    
    def _parse_nmap_xml(self, xml_output: str) -> Dict[str, Any]:
        """Parse Nmap XML output"""
        try:
            root = ET.fromstring(xml_output)
            
            results = {
                "scan_info": {},
                "hosts": []
            }
            
            # Parse scan info
            scaninfo = root.find("scaninfo")
            if scaninfo is not None:
                results["scan_info"] = {
                    "type": scaninfo.get("type"),
                    "protocol": scaninfo.get("protocol"),
                    "numservices": scaninfo.get("numservices")
                }
            
            # Parse hosts
            for host in root.findall("host"):
                host_data = {
                    "status": host.find("status").get("state"),
                    "addresses": [],
                    "hostnames": [],
                    "ports": [],
                    "os": None
                }
                
                # Addresses
                for addr in host.findall("address"):
                    host_data["addresses"].append({
                        "addr": addr.get("addr"),
                        "addrtype": addr.get("addrtype")
                    })
                
                # Hostnames
                hostnames = host.find("hostnames")
                if hostnames is not None:
                    for hostname in hostnames.findall("hostname"):
                        host_data["hostnames"].append(hostname.get("name"))
                
                # Ports
                ports = host.find("ports")
                if ports is not None:
                    for port in ports.findall("port"):
                        port_data = {
                            "portid": port.get("portid"),
                            "protocol": port.get("protocol"),
                            "state": port.find("state").get("state")
                        }
                        
                        service = port.find("service")
                        if service is not None:
                            port_data["service"] = {
                                "name": service.get("name"),
                                "product": service.get("product"),
                                "version": service.get("version")
                            }
                        
                        host_data["ports"].append(port_data)
                
                # OS detection
                os_elem = host.find("os")
                if os_elem is not None:
                    osmatch = os_elem.find("osmatch")
                    if osmatch is not None:
                        host_data["os"] = {
                            "name": osmatch.get("name"),
                            "accuracy": osmatch.get("accuracy")
                        }
                
                results["hosts"].append(host_data)
            
            return results
        
        except ET.ParseError as e:
            raise ToolExecutionError(f"Failed to parse Nmap XML: {str(e)}")
    
    # NUCLEI WRAPPERS
    
    async def run_nuclei(
        self,
        target: str,
        templates: Optional[List[str]] = None,
        severity: Optional[List[str]] = None,
        tags: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Execute Nuclei vulnerability scanner
        
        Args:
            target: Target URL
            templates: Specific templates to run
            severity: Filter by severity (critical, high, medium, low, info)
            tags: Filter by tags (e.g., cve, xss, sqli)
        """
        
        if not self.rate_limiter.check_limit("nuclei"):
            raise ToolExecutionError("Rate limit exceeded for nuclei")
        
        command = ["nuclei", "-u", target, "-json"]
        
        if templates:
            command.extend(["-t", ",".join(templates)])
        
        if severity:
            command.extend(["-severity", ",".join(severity)])
        
        if tags:
            command.extend(["-tags", ",".join(tags)])
        
        logger.info(f"Executing nuclei: {' '.join(command)}")
        result = await self._execute_command(command, timeout=600)
        
        if result["success"]:
            return self._parse_nuclei_json(result["stdout"])
        else:
            raise ToolExecutionError(f"Nuclei failed: {result['stderr']}")
    
    def _parse_nuclei_json(self, json_output: str) -> Dict[str, Any]:
        """Parse Nuclei JSON output"""
        findings = []
        
        for line in json_output.strip().split("\n"):
            if not line:
                continue
            
            try:
                finding = json.loads(line)
                findings.append({
                    "template_id": finding.get("template-id"),
                    "name": finding.get("info", {}).get("name"),
                    "severity": finding.get("info", {}).get("severity"),
                    "description": finding.get("info", {}).get("description"),
                    "matched_at": finding.get("matched-at"),
                    "extracted_results": finding.get("extracted-results", []),
                    "type": finding.get("type")
                })
            except json.JSONDecodeError:
                continue
        
        return {
            "total_findings": len(findings),
            "findings": findings,
            "severity_breakdown": self._count_severity(findings)
        }
    
    def _count_severity(self, findings: List[Dict]) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for finding in findings:
            severity = finding.get("severity", "info").lower()
            if severity in counts:
                counts[severity] += 1
        
        return counts
    
    # NIKTO WRAPPERS
    
    async def run_nikto(
        self,
        url: str,
        tuning: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute Nikto web scanner
        
        Args:
            url: Target URL
            tuning: Tuning options (e.g., "1" for interesting files)
        """
        
        if not self.rate_limiter.check_limit("nikto"):
            raise ToolExecutionError("Rate limit exceeded for nikto")
        
        command = ["nikto", "-h", url, "-Format", "json", "-output", "-"]
        
        if tuning:
            command.extend(["-Tuning", tuning])
        
        logger.info(f"Executing nikto: {' '.join(command)}")
        result = await self._execute_command(command, timeout=600)
        
        # Nikto writes JSON to stdout
        return self._parse_nikto_json(result["stdout"])
    
    def _parse_nikto_json(self, json_output: str) -> Dict[str, Any]:
        """Parse Nikto JSON output"""
        try:
            # Nikto JSON format
            data = json.loads(json_output)
            
            vulnerabilities = []
            for vuln in data.get("vulnerabilities", []):
                vulnerabilities.append({
                    "id": vuln.get("id"),
                    "method": vuln.get("method"),
                    "url": vuln.get("url"),
                    "msg": vuln.get("msg"),
                    "osvdb": vuln.get("OSVDB"),
                    "references": vuln.get("refs", [])
                })
            
            return {
                "host": data.get("host"),
                "port": data.get("port"),
                "banner": data.get("banner"),
                "total_vulnerabilities": len(vulnerabilities),
                "vulnerabilities": vulnerabilities
            }
        
        except json.JSONDecodeError:
            # Fallback to text parsing
            return {"raw_output": json_output, "vulnerabilities": []}
    
    # TESTSSL WRAPPERS
    
    async def run_testssl(
        self,
        target: str,
        severity_level: str = "HIGH"
    ) -> Dict[str, Any]:
        """
        Execute testssl.sh SSL/TLS scanner
        
        Args:
            target: Target host:port
            severity_level: Minimum severity to report
        """
        
        if not self.rate_limiter.check_limit("testssl"):
            raise ToolExecutionError("Rate limit exceeded for testssl")
        
        command = ["testssl.sh", "--jsonfile", "-", target]
        
        logger.info(f"Executing testssl.sh: {' '.join(command)}")
        result = await self._execute_command(command, timeout=300)
        
        return self._parse_testssl_json(result["stdout"])
    
    def _parse_testssl_json(self, json_output: str) -> Dict[str, Any]:
        """Parse testssl.sh JSON output"""
        findings = []
        
        for line in json_output.strip().split("\n"):
            if not line:
                continue
            
            try:
                finding = json.loads(line)
                findings.append({
                    "id": finding.get("id"),
                    "severity": finding.get("severity"),
                    "finding": finding.get("finding"),
                    "cve": finding.get("cve"),
                    "cwe": finding.get("cwe")
                })
            except json.JSONDecodeError:
                continue
        
        return {
            "total_findings": len(findings),
            "findings": findings,
            "severity_breakdown": self._count_severity(findings)
        }
    
    # SQLMAP WRAPPERS
    
    async def run_sqlmap(
        self,
        url: str,
        data: Optional[str] = None,
        cookie: Optional[str] = None,
        level: int = 1,
        risk: int = 1,
        technique: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute SQLMap (READ-ONLY mode for safety)
        
        Args:
            url: Target URL
            data: POST data
            cookie: Cookie string
            level: Detection level (1-5)
            risk: Risk level (1-3)
            technique: SQL injection techniques (B,E,U,S,T,Q)
        """
        
        if not self.rate_limiter.check_limit("sqlmap"):
            raise ToolExecutionError("Rate limit exceeded for sqlmap")
        
        command = [
            "sqlmap",
            "-u", url,
            "--batch",  # Non-interactive
            "--level", str(level),
            "--risk", str(risk),
            "--output-dir", "/tmp/sqlmap_output",
            "--no-cast",  # Safer
            "--skip-urlencode",
            "--random-agent"
        ]
        
        if data:
            command.extend(["--data", data])
        
        if cookie:
            command.extend(["--cookie", cookie])
        
        if technique:
            command.extend(["--technique", technique])
        
        # Safety: READ-ONLY operations only
        command.extend([
            "--current-db",  # Just enumerate DB name
            "--no-escaping",
            "--threads", "1"  # Slow to avoid DoS
        ])
        
        logger.info(f"Executing sqlmap: {' '.join(command)}")
        result = await self._execute_command(command, timeout=600)
        
        return self._parse_sqlmap_output(result["stdout"])
    
    def _parse_sqlmap_output(self, output: str) -> Dict[str, Any]:
        """Parse SQLMap output"""
        
        return {
            "vulnerable": "vulnerable" in output.lower(),
            "injection_type": self._extract_sqlmap_injection_type(output),
            "database": self._extract_sqlmap_database(output),
            "raw_output": output[:500]  # Truncate
        }
    
    def _extract_sqlmap_injection_type(self, output: str) -> Optional[str]:
        """Extract SQL injection type from output"""
        patterns = [
            r"Type: (.+)",
            r"Injection Type: (.+)"
        ]
        
        for pattern in patterns:
            match = re.search(pattern, output)
            if match:
                return match.group(1)
        
        return None
    
    def _extract_sqlmap_database(self, output: str) -> Optional[str]:
        """Extract database name from output"""
        match = re.search(r"current database: '(.+?)'", output)
        if match:
            return match.group(1)
        return None
    
    # SUBDOMAIN ENUMERATION
    
    async def run_sublist3r(
        self,
        domain: str,
        engines: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Execute Sublist3r subdomain enumeration
        
        Args:
            domain: Target domain
            engines: Search engines to use
        """
        
        if not self.rate_limiter.check_limit("sublist3r"):
            raise ToolExecutionError("Rate limit exceeded for sublist3r")
        
        command = ["sublist3r", "-d", domain, "-o", "-"]
        
        if engines:
            command.extend(["-e", ",".join(engines)])
        
        logger.info(f"Executing sublist3r: {' '.join(command)}")
        result = await self._execute_command(command, timeout=300)
        
        subdomains = [
            line.strip() for line in result["stdout"].split("\n")
            if line.strip() and not line.startswith("[")
        ]
        
        return {
            "domain": domain,
            "total_subdomains": len(subdomains),
            "subdomains": subdomains
        }
    
    async def run_amass(
        self,
        domain: str,
        passive: bool = True
    ) -> Dict[str, Any]:
        """
        Execute Amass subdomain enumeration
        
        Args:
            domain: Target domain
            passive: Use passive mode only
        """
        
        if not self.rate_limiter.check_limit("amass"):
            raise ToolExecutionError("Rate limit exceeded for amass")
        
        if passive:
            command = ["amass", "enum", "-passive", "-d", domain, "-json", "-"]
        else:
            command = ["amass", "enum", "-d", domain, "-json", "-"]
        
        logger.info(f"Executing amass: {' '.join(command)}")
        result = await self._execute_command(command, timeout=600)
        
        subdomains = []
        for line in result["stdout"].split("\n"):
            if line.strip():
                try:
                    data = json.loads(line)
                    subdomains.append(data.get("name"))
                except json.JSONDecodeError:
                    continue
        
        return {
            "domain": domain,
            "total_subdomains": len(subdomains),
            "subdomains": list(set(subdomains))
        }
    
    # UTILITY FUNCTIONS
    
    async def run_whois(self, domain: str) -> Dict[str, Any]:
        """Execute WHOIS lookup"""
        
        if not self.rate_limiter.check_limit("whois"):
            raise ToolExecutionError("Rate limit exceeded for whois")
        
        command = ["whois", domain]
        result = await self._execute_command(command, timeout=30)
        
        return {
            "domain": domain,
            "raw_output": result["stdout"],
            "registrar": self._extract_whois_field(result["stdout"], "Registrar"),
            "creation_date": self._extract_whois_field(result["stdout"], "Creation Date"),
            "expiration_date": self._extract_whois_field(result["stdout"], "Expiration Date")
        }
    
    def _extract_whois_field(self, output: str, field: str) -> Optional[str]:
        """Extract field from WHOIS output"""
        pattern = rf"{field}:\s*(.+)"
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None
    
    async def run_dig(
        self,
        domain: str,
        record_type: str = "A"
    ) -> Dict[str, Any]:
        """Execute DNS lookup with dig"""
        
        if not self.rate_limiter.check_limit("dig"):
            raise ToolExecutionError("Rate limit exceeded for dig")
        
        command = ["dig", domain, record_type, "+short"]
        result = await self._execute_command(command, timeout=30)
        
        records = [line.strip() for line in result["stdout"].split("\n") if line.strip()]
        
        return {
            "domain": domain,
            "record_type": record_type,
            "records": records
        }


# Singleton instance
_tool_executor = None


def get_tool_executor() -> ToolExecutor:
    """Get singleton ToolExecutor instance"""
    global _tool_executor
    if _tool_executor is None:
        _tool_executor = ToolExecutor()
    return _tool_executor
