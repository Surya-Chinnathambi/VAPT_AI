"""
Enhanced Docker Security Tools Manager
Orchestrates 88+ security tools in Docker containers with intelligent execution
"""
import asyncio
import json
import logging
import os
import re
import time
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import docker
from docker.errors import DockerException, APIError, ContainerError, ImageNotFound

from core.ai_security_prompts import get_tool_config

logger = logging.getLogger(__name__)

class EnhancedDockerToolManager:
    """
    Advanced Docker tool manager with:
    - Parallel execution
    - Resource management
    - Auto-scaling
    - Tool chaining
    - Result correlation
    """
    
    def __init__(self):
        """Initialize enhanced Docker manager"""
        try:
            self.client = docker.from_env()
            self.client.ping()
            self.active_containers = {}
            self.tool_queue = asyncio.Queue()
            self.results_cache = {}
            logger.info("✅ Enhanced Docker Tool Manager initialized")
        except DockerException as e:
            logger.error(f"❌ Docker initialization failed: {e}")
            raise
    
    async def pull_security_images(self, tools: List[str] = None) -> Dict:
        """
        Pull all required security tool images
        
        Args:
            tools: List of tool names, or None for all
            
        Returns:
            Dict with pull status for each tool
        """
        if tools is None:
            tools = [
                "nmap", "nuclei", "nikto", "trivy", "sqlmap", 
                "wpscan", "testssl", "sublist3r", "amass", "zaproxy"
            ]
        
        results = {}
        logger.info(f"📥 Pulling {len(tools)} security tool images...")
        
        for tool in tools:
            config = get_tool_config(tool)
            if not config or 'docker_image' not in config:
                results[tool] = {"success": False, "error": "No Docker config"}
                continue
            
            image = config['docker_image']
            try:
                logger.info(f"  🔄 Pulling {tool} ({image})...")
                self.client.images.pull(image)
                results[tool] = {"success": True, "image": image}
                logger.info(f"  ✅ {tool} ready")
            except Exception as e:
                results[tool] = {"success": False, "error": str(e)}
                logger.error(f"  ❌ {tool} failed: {e}")
        
        success_count = sum(1 for r in results.values() if r.get('success'))
        logger.info(f"✅ Pull complete: {success_count}/{len(tools)} successful")
        
        return results
    
    async def run_tool(
        self,
        tool_name: str,
        target: str,
        scan_type: str = "standard",
        extra_args: List[str] = None,
        timeout: int = None
    ) -> Dict:
        """
        Run a security tool in Docker container
        
        Args:
            tool_name: Name of tool (nmap, nuclei, etc.)
            target: Target to scan
            scan_type: Scan intensity (quick/standard/full)
            extra_args: Additional command-line arguments
            timeout: Override default timeout
            
        Returns:
            Dict with tool output and metadata
        """
        start_time = time.time()
        config = get_tool_config(tool_name)
        
        if not config:
            return {
                "success": False,
                "error": f"Unknown tool: {tool_name}",
                "tool": tool_name
            }
        
        image = config['docker_image']
        timeout = timeout or config.get('timeout', 3600)
        
        # Build command based on tool
        command = self._build_command(tool_name, target, scan_type, extra_args, config)
        
        logger.info(f"🔧 Running {tool_name} on {target} (scan_type: {scan_type})")
        logger.debug(f"   Command: {command}")
        
        try:
            # Ensure image exists
            try:
                self.client.images.get(image)
            except ImageNotFound:
                logger.info(f"   📥 Pulling {image}...")
                self.client.images.pull(image)
            
            # Security constraints
            container_opts = {
                'image': image,
                'command': command,
                'remove': True,  # Auto-remove after completion
                'detach': False,  # Wait for completion
                'network_mode': 'bridge',
                'mem_limit': '1g',
                'cpu_period': 100000,
                'cpu_quota': 100000,  # 1 CPU
                'security_opt': ['no-new-privileges:true'],
                'cap_drop': ['ALL'],
            }
            
            # Tool-specific adjustments
            if tool_name.lower() == 'nmap':
                container_opts['cap_add'] = ['NET_RAW']
                container_opts['privileged'] = True  # Windows Docker Desktop requirement
            
            # Run container
            output = self.client.containers.run(**container_opts)
            
            # Parse output
            decoded_output = output.decode('utf-8', errors='replace')
            parsed = self._parse_tool_output(tool_name, decoded_output)
            
            duration = time.time() - start_time
            
            return {
                "success": True,
                "tool": tool_name,
                "target": target,
                "scan_type": scan_type,
                "output": decoded_output,
                "parsed": parsed,
                "duration": round(duration, 2),
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except ContainerError as e:
            logger.error(f"❌ {tool_name} container error: {e}")
            return {
                "success": False,
                "tool": tool_name,
                "error": f"Container error: {e}",
                "duration": time.time() - start_time
            }
        except Exception as e:
            logger.error(f"❌ {tool_name} execution failed: {e}")
            return {
                "success": False,
                "tool": tool_name,
                "error": str(e),
                "duration": time.time() - start_time
            }
    
    async def run_parallel(
        self,
        tasks: List[Dict]
    ) -> List[Dict]:
        """
        Run multiple tools in parallel
        
        Args:
            tasks: List of task dicts with tool_name, target, scan_type
            
        Returns:
            List of results in same order as tasks
            
        Example:
            tasks = [
                {"tool_name": "nmap", "target": "example.com", "scan_type": "quick"},
                {"tool_name": "nuclei", "target": "https://example.com", "scan_type": "standard"},
                {"tool_name": "nikto", "target": "https://example.com", "scan_type": "quick"}
            ]
        """
        logger.info(f"🚀 Running {len(tasks)} tools in parallel...")
        
        # Create async tasks
        async_tasks = []
        for task in tasks:
            async_tasks.append(
                self.run_tool(
                    task['tool_name'],
                    task['target'],
                    task.get('scan_type', 'standard'),
                    task.get('extra_args'),
                    task.get('timeout')
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
        logger.info(f"✅ Parallel execution complete: {success_count}/{len(tasks)} successful")
        
        return final_results
    
    async def run_scan_phase(
        self,
        phase: str,
        target: str,
        intensity: str = "standard"
    ) -> Dict:
        """
        Run a complete scan phase with appropriate tools
        
        Args:
            phase: reconnaissance/scanning/exploitation
            target: Target to scan
            intensity: quick/standard/full
            
        Returns:
            Dict with phase results
        """
        phase_tools = self._get_phase_tools(phase, target)
        
        if not phase_tools:
            return {
                "success": False,
                "error": f"No tools defined for phase: {phase}"
            }
        
        logger.info(f"📋 Phase: {phase.upper()} - Running {len(phase_tools)} tools")
        
        # Adjust scan types based on intensity
        scan_type_map = {
            "quick": "quick",
            "standard": "standard",
            "full": "full"
        }
        scan_type = scan_type_map.get(intensity, "standard")
        
        # Prepare tasks
        tasks = [
            {
                "tool_name": tool,
                "target": target,
                "scan_type": scan_type
            }
            for tool in phase_tools
        ]
        
        # Run in parallel
        results = await self.run_parallel(tasks)
        
        # Aggregate results
        return {
            "success": True,
            "phase": phase,
            "target": target,
            "intensity": intensity,
            "tools_run": len(phase_tools),
            "tools_successful": sum(1 for r in results if r.get('success')),
            "results": results,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def _get_phase_tools(self, phase: str, target: str) -> List[str]:
        """Determine which tools to use for a phase"""
        is_web = target.startswith('http')
        
        if phase == "reconnaissance":
            tools = ["nmap"]
            if is_web:
                tools.extend(["sublist3r", "testssl"])
            return tools
        
        elif phase == "scanning":
            if is_web:
                return ["nuclei", "nikto", "zaproxy"]
            else:
                return ["nmap"]
        
        elif phase == "exploitation":
            if is_web:
                return ["sqlmap", "xsstrike"]
            else:
                return ["metasploit"]
        
        return []
    
    def _build_command(
        self,
        tool_name: str,
        target: str,
        scan_type: str,
        extra_args: List[str],
        config: Dict
    ) -> str:
        """Build tool-specific command"""
        tool = tool_name.lower()
        
        if tool == "nmap":
            scan_args = config['scan_types'].get(scan_type, "-T4 -F")
            cmd = f"nmap {scan_args} {target}"
        
        elif tool == "nuclei":
            scan_args = config['scan_types'].get(scan_type, "-t cves/ -t vulnerabilities/")
            cmd = f"nuclei -u {target} {scan_args} -json"
        
        elif tool == "nikto":
            scan_args = config['scan_types'].get(scan_type, "-Tuning 1,2,3")
            cmd = f"nikto -h {target} {scan_args}"
        
        elif tool == "trivy":
            scan_args = config['scan_types'].get(scan_type, "image")
            cmd = f"trivy {scan_args} {target}"
        
        elif tool == "sqlmap":
            scan_args = config['scan_types'].get(scan_type, "--batch --level=1 --risk=1")
            cmd = f"sqlmap -u {target} {scan_args}"
        
        elif tool == "wpscan":
            scan_args = config['scan_types'].get(scan_type, "--enumerate vp,vt")
            cmd = f"wpscan --url {target} {scan_args} --format json"
        
        elif tool == "testssl":
            scan_args = config['scan_types'].get(scan_type, "--protocols --ciphers")
            cmd = f"testssl.sh {scan_args} {target}"
        
        elif tool == "sublist3r":
            domain = target.replace('http://', '').replace('https://', '').split('/')[0]
            cmd = f"sublist3r -d {domain}"
        
        elif tool == "zaproxy":
            scan_script = config['scan_types'].get(scan_type, "zap-baseline.py")
            cmd = f"{scan_script} -t {target}"
        
        else:
            cmd = f"{tool} {target}"
        
        # Add extra args
        if extra_args:
            cmd += " " + " ".join(extra_args)
        
        return cmd
    
    def _parse_tool_output(self, tool_name: str, output: str) -> Dict:
        """Parse tool output into structured format"""
        tool = tool_name.lower()
        
        try:
            if tool == "nuclei":
                # Nuclei outputs JSON
                lines = output.strip().split('\n')
                findings = []
                for line in lines:
                    if line.startswith('{'):
                        try:
                            findings.append(json.loads(line))
                        except:
                            pass
                return {"findings": findings, "count": len(findings)}
            
            elif tool == "nmap":
                # Parse Nmap output
                open_ports = []
                for line in output.split('\n'):
                    if '/tcp' in line or '/udp' in line:
                        match = re.search(r'(\d+)/(tcp|udp)\s+(\w+)\s+(.*)', line)
                        if match:
                            open_ports.append({
                                "port": match.group(1),
                                "protocol": match.group(2),
                                "state": match.group(3),
                                "service": match.group(4).strip()
                            })
                return {"open_ports": open_ports, "count": len(open_ports)}
            
            elif tool == "nikto":
                # Parse Nikto findings
                findings = []
                for line in output.split('\n'):
                    if line.startswith('+'):
                        findings.append(line[1:].strip())
                return {"findings": findings, "count": len(findings)}
            
            elif tool == "trivy":
                # Trivy outputs JSON
                try:
                    data = json.loads(output)
                    return data
                except:
                    return {"raw": output}
            
            elif tool == "wpscan":
                # WPScan outputs JSON
                try:
                    data = json.loads(output)
                    return data
                except:
                    return {"raw": output}
            
            else:
                # Generic parsing
                return {"raw": output, "lines": len(output.split('\n'))}
        
        except Exception as e:
            logger.error(f"Parse error for {tool_name}: {e}")
            return {"raw": output, "parse_error": str(e)}
    
    async def get_tool_info(self) -> Dict:
        """Get information about available tools"""
        tools = {}
        
        for tool_name in ["nmap", "nuclei", "nikto", "trivy", "sqlmap", 
                          "wpscan", "testssl", "sublist3r", "zaproxy"]:
            config = get_tool_config(tool_name)
            if config:
                # Check if image is pulled
                try:
                    self.client.images.get(config['docker_image'])
                    image_status = "ready"
                except ImageNotFound:
                    image_status = "not_pulled"
                
                tools[tool_name] = {
                    "image": config['docker_image'],
                    "status": image_status,
                    "scan_types": list(config.get('scan_types', {}).keys()),
                    "timeout": config.get('timeout', 3600),
                    "description": self._get_tool_description(tool_name)
                }
        
        return tools
    
    def _get_tool_description(self, tool_name: str) -> str:
        """Get human-readable tool description"""
        descriptions = {
            "nmap": "Network mapper - Port scanning and service detection",
            "nuclei": "Fast vulnerability scanner with 5000+ templates",
            "nikto": "Web server scanner - Detects misconfigurations and vulnerabilities",
            "trivy": "Container vulnerability scanner - CVE detection",
            "sqlmap": "Automated SQL injection detection and exploitation",
            "wpscan": "WordPress security scanner - Plugin/theme vulnerabilities",
            "testssl": "SSL/TLS security checker - Protocol and cipher analysis",
            "sublist3r": "Subdomain enumeration tool - Asset discovery",
            "zaproxy": "OWASP ZAP - Comprehensive web application scanner",
            "amass": "OWASP Amass - Advanced subdomain enumeration",
            "metasploit": "Exploitation framework - PoC validation"
        }
        return descriptions.get(tool_name, "Security testing tool")
    
    def cleanup(self):
        """Cleanup resources"""
        try:
            # Stop any running containers
            for container_id in list(self.active_containers.keys()):
                try:
                    container = self.client.containers.get(container_id)
                    container.stop(timeout=5)
                    logger.info(f"Stopped container: {container_id}")
                except:
                    pass
            
            self.active_containers.clear()
            logger.info("✅ Cleanup complete")
        except Exception as e:
            logger.error(f"Cleanup error: {e}")


# Global instance
_docker_manager = None

def get_enhanced_docker_manager() -> EnhancedDockerToolManager:
    """Get singleton instance of enhanced Docker manager"""
    global _docker_manager
    if _docker_manager is None:
        _docker_manager = EnhancedDockerToolManager()
    return _docker_manager
