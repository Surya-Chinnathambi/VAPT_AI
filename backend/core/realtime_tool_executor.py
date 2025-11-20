"""
Real-Time Tool Executor for 88+ Security Tools
Streams live progress, logs, and results via WebSocket
"""
import asyncio
import json
import logging
from typing import Dict, List, Optional, Callable
from datetime import datetime
import docker
from docker.models.containers import Container

from core.ai_security_prompts import TOOL_CONFIGS, get_tool_config

logger = logging.getLogger(__name__)


class RealtimeToolExecutor:
    """
    Executes security tools with real-time streaming updates
    
    Features:
    - Live log streaming (line-by-line)
    - Progress percentage tracking
    - Vulnerability detection alerts
    - Parallel execution monitoring
    - Tool status updates
    """
    
    def __init__(self):
        try:
            self.client = docker.from_env()
            self.docker_available = True
        except Exception as e:
            logger.warning(f"Docker not available: {e}")
            self.docker_available = False
        
        self.active_executions: Dict[str, Container] = {}
        self.execution_stats: Dict[str, Dict] = {}
    
    async def execute_tool_realtime(
        self,
        tool_name: str,
        target: str,
        scan_type: str = "standard",
        extra_args: Optional[List[str]] = None,
        timeout: Optional[int] = None,
        progress_callback: Optional[Callable] = None
    ) -> Dict:
        """
        Execute single tool with real-time streaming
        
        Args:
            tool_name: Name of security tool (nmap, nuclei, nikto, etc.)
            target: Target URL/IP to scan
            scan_type: quick/standard/full/aggressive
            extra_args: Additional command arguments
            timeout: Max execution time in seconds
            progress_callback: Async callback for real-time updates
        
        Returns:
            {
                "success": True,
                "tool": "nmap",
                "duration": 45.2,
                "findings_count": 12,
                "parsed_results": {...},
                "raw_output": "..."
            }
        """
        if not self.docker_available:
            return {
                "success": False,
                "error": "Docker not available",
                "tool": tool_name
            }
        
        # Get tool configuration
        config = get_tool_config(tool_name)
        if not config:
            return {
                "success": False,
                "error": f"Unknown tool: {tool_name}",
                "tool": tool_name
            }
        
        execution_id = f"{tool_name}_{datetime.now().timestamp()}"
        start_time = datetime.now()
        
        # Send start notification
        if progress_callback:
            await progress_callback({
                "type": "tool_start",
                "tool": tool_name,
                "target": target,
                "scan_type": scan_type,
                "timestamp": start_time.isoformat()
            })
        
        try:
            # Build command
            command = self._build_command(tool_name, target, scan_type, extra_args, config)
            
            # Container security options
            container_opts = {
                'detach': True,
                'remove': True,
                'network_mode': 'bridge',
                'mem_limit': config.get('memory_limit', '1g'),
                'cpu_quota': config.get('cpu_quota', 100000),
                'security_opt': ['no-new-privileges:true'],
                'cap_drop': ['ALL']
            }
            
            # Tool-specific capabilities
            if tool_name == 'nmap':
                container_opts['cap_add'] = ['NET_RAW', 'NET_ADMIN']
                container_opts['privileged'] = False  # Prefer capabilities over privileged
            elif tool_name in ['masscan', 'zmap']:
                container_opts['cap_add'] = ['NET_RAW']
            
            # Pull image if needed
            image = config['docker_image']
            try:
                self.client.images.get(image)
            except docker.errors.ImageNotFound:
                if progress_callback:
                    await progress_callback({
                        "type": "image_pull",
                        "tool": tool_name,
                        "image": image,
                        "status": "pulling"
                    })
                self.client.images.pull(image)
            
            # Start container
            container = self.client.containers.run(
                image,
                command,
                **container_opts
            )
            
            self.active_executions[execution_id] = container
            
            # Stream logs in real-time
            raw_output = await self._stream_container_logs(
                container,
                tool_name,
                execution_id,
                progress_callback,
                timeout or config.get('timeout', 1800)
            )
            
            # Wait for completion
            exit_code = container.wait()
            duration = (datetime.now() - start_time).total_seconds()
            
            # Parse results
            parsed_results = self._parse_tool_output(tool_name, raw_output)
            
            # Send completion notification
            if progress_callback:
                await progress_callback({
                    "type": "tool_complete",
                    "tool": tool_name,
                    "duration": duration,
                    "findings_count": parsed_results.get('findings_count', 0),
                    "success": exit_code['StatusCode'] == 0,
                    "timestamp": datetime.now().isoformat()
                })
            
            return {
                "success": exit_code['StatusCode'] == 0,
                "tool": tool_name,
                "target": target,
                "scan_type": scan_type,
                "duration": duration,
                "findings_count": parsed_results.get('findings_count', 0),
                "parsed_results": parsed_results,
                "raw_output": raw_output,
                "exit_code": exit_code['StatusCode']
            }
        
        except asyncio.TimeoutError:
            if execution_id in self.active_executions:
                self.active_executions[execution_id].stop(timeout=5)
            
            return {
                "success": False,
                "error": f"Timeout after {timeout}s",
                "tool": tool_name,
                "duration": timeout
            }
        
        except Exception as e:
            logger.error(f"Tool execution error ({tool_name}): {e}")
            
            if progress_callback:
                await progress_callback({
                    "type": "tool_error",
                    "tool": tool_name,
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                })
            
            return {
                "success": False,
                "error": str(e),
                "tool": tool_name
            }
        
        finally:
            if execution_id in self.active_executions:
                del self.active_executions[execution_id]
    
    async def _stream_container_logs(
        self,
        container: Container,
        tool_name: str,
        execution_id: str,
        progress_callback: Optional[Callable],
        timeout: int
    ) -> str:
        """
        Stream container logs line-by-line with real-time updates
        """
        raw_output = []
        line_count = 0
        findings_count = 0
        
        try:
            async for log_chunk in self._async_log_iterator(container, timeout):
                log_text = log_chunk.decode('utf-8', errors='ignore').strip()
                
                if not log_text:
                    continue
                
                raw_output.append(log_text)
                line_count += 1
                
                # Send log line
                if progress_callback:
                    await progress_callback({
                        "type": "log",
                        "tool": tool_name,
                        "line": log_text,
                        "line_number": line_count,
                        "timestamp": datetime.now().isoformat()
                    })
                
                # Real-time vulnerability detection
                vuln_detected = self._detect_vulnerability(tool_name, log_text)
                if vuln_detected:
                    findings_count += 1
                    if progress_callback:
                        await progress_callback({
                            "type": "vulnerability_found",
                            "tool": tool_name,
                            "vulnerability": vuln_detected,
                            "findings_count": findings_count,
                            "timestamp": datetime.now().isoformat()
                        })
                
                # Progress estimation
                if line_count % 50 == 0 and progress_callback:
                    progress = self._estimate_progress(tool_name, line_count)
                    await progress_callback({
                        "type": "progress",
                        "tool": tool_name,
                        "percentage": progress,
                        "lines_processed": line_count,
                        "timestamp": datetime.now().isoformat()
                    })
        
        except asyncio.TimeoutError:
            logger.warning(f"Log streaming timeout for {tool_name}")
        
        return "\n".join(raw_output)
    
    async def _async_log_iterator(self, container: Container, timeout: int):
        """Convert blocking log iterator to async"""
        loop = asyncio.get_event_loop()
        
        async def read_logs():
            for log in container.logs(stream=True, follow=True):
                yield log
        
        start_time = asyncio.get_event_loop().time()
        async for log in read_logs():
            if asyncio.get_event_loop().time() - start_time > timeout:
                raise asyncio.TimeoutError()
            yield log
    
    def _build_command(
        self,
        tool_name: str,
        target: str,
        scan_type: str,
        extra_args: Optional[List[str]],
        config: Dict
    ) -> str:
        """Build tool-specific command"""
        scan_templates = config.get('scan_types', {})
        base_args = scan_templates.get(scan_type, scan_templates.get('standard', ''))
        
        if tool_name == "nmap":
            cmd = f"nmap {base_args} {target}"
        
        elif tool_name == "nuclei":
            templates = scan_templates.get(scan_type, '-t cves/ -t vulnerabilities/')
            cmd = f"nuclei {templates} -u {target} -json"
        
        elif tool_name == "nikto":
            cmd = f"nikto -h {target} {base_args}"
        
        elif tool_name == "trivy":
            if target.startswith('http'):
                cmd = f"trivy image --severity HIGH,CRITICAL {target}"
            else:
                cmd = f"trivy fs --severity HIGH,CRITICAL {target}"
        
        elif tool_name == "sqlmap":
            cmd = f"sqlmap -u {target} --batch --random-agent {base_args}"
        
        elif tool_name == "wpscan":
            cmd = f"wpscan --url {target} {base_args}"
        
        elif tool_name == "testssl":
            cmd = f"testssl.sh {base_args} {target}"
        
        elif tool_name == "sublist3r":
            domain = target.replace('http://', '').replace('https://', '').split('/')[0]
            cmd = f"sublist3r -d {domain}"
        
        elif tool_name == "amass":
            domain = target.replace('http://', '').replace('https://', '').split('/')[0]
            cmd = f"amass enum -d {domain}"
        
        elif tool_name == "zaproxy":
            cmd = f"zap-baseline.py -t {target} {base_args}"
        
        elif tool_name == "sslyze":
            cmd = f"sslyze {target} {base_args}"
        
        elif tool_name == "xsstrike":
            cmd = f"xsstrike -u {target} {base_args}"
        
        elif tool_name == "gobuster":
            cmd = f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt {base_args}"
        
        elif tool_name == "ffuf":
            cmd = f"ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt {base_args}"
        
        elif tool_name == "dirsearch":
            cmd = f"dirsearch -u {target} {base_args}"
        
        elif tool_name == "hydra":
            cmd = f"hydra {base_args} {target}"
        
        elif tool_name == "masscan":
            cmd = f"masscan {target} {base_args}"
        
        elif tool_name == "metasploit":
            cmd = f"msfconsole -x '{base_args}'"
        
        else:
            # Generic command format
            cmd = f"{tool_name} {base_args} {target}"
        
        # Add extra arguments
        if extra_args:
            cmd += " " + " ".join(extra_args)
        
        return cmd
    
    def _detect_vulnerability(self, tool_name: str, log_line: str) -> Optional[Dict]:
        """
        Real-time vulnerability detection from log output
        """
        log_lower = log_line.lower()
        
        # Nmap port detection
        if tool_name == "nmap" and "/tcp" in log_line and "open" in log_lower:
            return {
                "type": "open_port",
                "severity": "info",
                "details": log_line.strip()
            }
        
        # Nuclei template match
        if tool_name == "nuclei" and "[" in log_line and "]" in log_line:
            if "critical" in log_lower:
                severity = "critical"
            elif "high" in log_lower:
                severity = "high"
            elif "medium" in log_lower:
                severity = "medium"
            else:
                severity = "low"
            
            return {
                "type": "nuclei_finding",
                "severity": severity,
                "details": log_line.strip()
            }
        
        # Nikto vulnerability
        if tool_name == "nikto" and ("osvdb" in log_lower or "cve-" in log_lower):
            return {
                "type": "web_vulnerability",
                "severity": "medium",
                "details": log_line.strip()
            }
        
        # SQLMap injection
        if tool_name == "sqlmap" and ("vulnerable" in log_lower or "injection" in log_lower):
            return {
                "type": "sql_injection",
                "severity": "critical",
                "details": log_line.strip()
            }
        
        # XSS detection
        if tool_name == "xsstrike" and "xss" in log_lower and "found" in log_lower:
            return {
                "type": "xss",
                "severity": "high",
                "details": log_line.strip()
            }
        
        # Generic CVE detection
        if "cve-" in log_lower:
            return {
                "type": "cve",
                "severity": "high",
                "details": log_line.strip()
            }
        
        return None
    
    def _estimate_progress(self, tool_name: str, lines_processed: int) -> int:
        """
        Estimate progress percentage based on tool and output lines
        """
        # Tool-specific progress estimation
        estimations = {
            "nmap": min(90, int((lines_processed / 1000) * 100)),  # Nmap typically 1000+ lines
            "nuclei": min(85, int((lines_processed / 5000) * 100)),  # Nuclei can be 5000+ templates
            "nikto": min(90, int((lines_processed / 2000) * 100)),
            "sqlmap": min(80, int((lines_processed / 500) * 100)),
            "trivy": min(90, int((lines_processed / 300) * 100)),
            "wpscan": min(85, int((lines_processed / 800) * 100)),
        }
        
        return estimations.get(tool_name, min(90, int((lines_processed / 500) * 100)))
    
    def _parse_tool_output(self, tool_name: str, output: str) -> Dict:
        """
        Parse tool output into structured results
        """
        findings = []
        findings_count = 0
        
        if tool_name == "nuclei":
            # Parse JSON output
            for line in output.split('\n'):
                if line.strip().startswith('{'):
                    try:
                        finding = json.loads(line)
                        findings.append(finding)
                        findings_count += 1
                    except json.JSONDecodeError:
                        pass
        
        elif tool_name == "nmap":
            # Parse open ports
            for line in output.split('\n'):
                if '/tcp' in line and 'open' in line.lower():
                    findings.append({"type": "open_port", "details": line.strip()})
                    findings_count += 1
        
        elif tool_name == "nikto":
            # Parse findings
            for line in output.split('\n'):
                if 'OSVDB-' in line or 'CVE-' in line:
                    findings.append({"type": "web_vuln", "details": line.strip()})
                    findings_count += 1
        
        elif tool_name == "sqlmap":
            # Parse SQL injection results
            if 'vulnerable' in output.lower():
                findings.append({"type": "sql_injection", "vulnerable": True})
                findings_count += 1
        
        elif tool_name == "trivy":
            # Parse CVEs
            for line in output.split('\n'):
                if 'CVE-' in line:
                    findings.append({"type": "cve", "details": line.strip()})
                    findings_count += 1
        
        return {
            "findings": findings,
            "findings_count": findings_count,
            "raw_output_length": len(output)
        }
    
    async def execute_parallel_realtime(
        self,
        tasks: List[Dict],
        progress_callback: Optional[Callable] = None
    ) -> List[Dict]:
        """
        Execute multiple tools in parallel with real-time updates
        
        Args:
            tasks: List of {"tool_name": "...", "target": "...", "scan_type": "..."}
            progress_callback: Callback for all tool updates
        
        Returns:
            List of execution results
        """
        if progress_callback:
            await progress_callback({
                "type": "parallel_start",
                "tools_count": len(tasks),
                "tools": [t['tool_name'] for t in tasks],
                "timestamp": datetime.now().isoformat()
            })
        
        # Create individual progress callbacks for each tool
        async_tasks = []
        for task in tasks:
            async_tasks.append(
                self.execute_tool_realtime(
                    task['tool_name'],
                    task['target'],
                    task.get('scan_type', 'standard'),
                    task.get('extra_args'),
                    task.get('timeout'),
                    progress_callback
                )
            )
        
        # Execute all in parallel
        results = await asyncio.gather(*async_tasks, return_exceptions=True)
        
        # Handle exceptions
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                final_results.append({
                    "success": False,
                    "tool": tasks[i]['tool_name'],
                    "error": str(result)
                })
            else:
                final_results.append(result)
        
        success_count = sum(1 for r in final_results if r.get('success'))
        
        if progress_callback:
            await progress_callback({
                "type": "parallel_complete",
                "tools_count": len(tasks),
                "success_count": success_count,
                "results_summary": [
                    {
                        "tool": r.get('tool'),
                        "success": r.get('success'),
                        "findings": r.get('findings_count', 0)
                    }
                    for r in final_results
                ],
                "timestamp": datetime.now().isoformat()
            })
        
        return final_results


# Singleton instance
_realtime_executor = None

def get_realtime_executor() -> RealtimeToolExecutor:
    """Get singleton instance of real-time executor"""
    global _realtime_executor
    if _realtime_executor is None:
        _realtime_executor = RealtimeToolExecutor()
    return _realtime_executor
