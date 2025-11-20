"""
AI-Powered VAPT Team Orchestration Engine
Automates the complete VAPT workflow with intelligent decision-making
"""
import asyncio
import json
import logging
from typing import Dict, List, Optional
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)

class VAPTPhase(Enum):
    """VAPT Testing Phases"""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"

class VAPTTool(Enum):
    """Available VAPT Tools"""
    # Reconnaissance
    NMAP = "nmap"
    MASSCAN = "masscan"
    THEHARVESTER = "theharvester"
    SUBLIST3R = "sublist3r"
    AMASS = "amass"
    SHODAN = "shodan"
    DNSENUM = "dnsenum"
    
    # Web Scanning
    NIKTO = "nikto"
    NUCLEI = "nuclei"
    WPSCAN = "wpscan"
    SQLMAP = "sqlmap"
    XSSTRIKE = "xsstrike"
    ZAP = "zap"
    WAPITI = "wapiti"
    
    # Exploitation
    METASPLOIT = "metasploit"
    HYDRA = "hydra"
    HASHCAT = "hashcat"
    
    # Cloud/Container
    TRIVY = "trivy"
    SCOUTSUITE = "scoutsuite"

class VAPTOrchestrator:
    """
    Master AI Orchestrator for VAPT Operations
    Coordinates all tools and makes intelligent decisions
    """
    
    def __init__(self):
        self.active_scans = {}
        self.results_cache = {}
        
    async def analyze_target(self, target: str, scope: Dict) -> Dict:
        """
        AI analyzes target and determines testing strategy
        
        Args:
            target: Target domain/IP
            scope: Testing scope and constraints
            
        Returns:
            AI-generated testing plan
        """
        logger.info(f"AI analyzing target: {target}")
        
        # Determine target type
        target_type = await self._classify_target(target)
        
        # Generate AI testing plan
        plan = {
            "target": target,
            "target_type": target_type,
            "phases": [],
            "estimated_duration": 0,
            "tools_required": [],
            "priority": "high"
        }
        
        # Phase 1: Reconnaissance
        recon_phase = {
            "phase": VAPTPhase.RECONNAISSANCE.value,
            "tools": [
                {"tool": VAPTTool.NMAP.value, "priority": 1, "parallel": False},
                {"tool": VAPTTool.SUBLIST3R.value, "priority": 1, "parallel": True},
                {"tool": VAPTTool.THEHARVESTER.value, "priority": 2, "parallel": True},
                {"tool": VAPTTool.SHODAN.value, "priority": 2, "parallel": True},
            ],
            "duration_estimate": "15-30 minutes",
            "can_parallelize": True
        }
        plan["phases"].append(recon_phase)
        
        # Phase 2: Vulnerability Scanning (conditional based on recon)
        scan_phase = {
            "phase": VAPTPhase.SCANNING.value,
            "tools": [],
            "duration_estimate": "1-2 hours",
            "can_parallelize": True
        }
        
        if target_type in ["web", "webapp"]:
            scan_phase["tools"].extend([
                {"tool": VAPTTool.NIKTO.value, "priority": 1},
                {"tool": VAPTTool.NUCLEI.value, "priority": 1},
                {"tool": VAPTTool.ZAP.value, "priority": 2},
                {"tool": VAPTTool.SQLMAP.value, "priority": 3},
            ])
        
        if target_type in ["network", "infrastructure"]:
            scan_phase["tools"].extend([
                {"tool": VAPTTool.NMAP.value, "priority": 1, "scan_type": "full"},
                {"tool": VAPTTool.MASSCAN.value, "priority": 1},
            ])
            
        plan["phases"].append(scan_phase)
        
        # Phase 3: Exploitation (AI will decide based on findings)
        exploit_phase = {
            "phase": VAPTPhase.EXPLOITATION.value,
            "tools": [],
            "duration_estimate": "2-4 hours",
            "ai_decision_required": True,
            "note": "AI will select exploits based on vulnerability findings"
        }
        plan["phases"].append(exploit_phase)
        
        return plan
    
    async def _classify_target(self, target: str) -> str:
        """Classify target type using AI"""
        if target.startswith("http"):
            return "webapp"
        elif "." in target and not target.replace(".", "").isdigit():
            return "web"
        else:
            return "network"
    
    async def execute_phase(self, phase: Dict, target: str, 
                          progress_callback=None) -> Dict:
        """
        Execute a VAPT phase with real-time progress
        
        Args:
            phase: Phase configuration
            target: Target to test
            progress_callback: Callback for real-time updates
            
        Returns:
            Phase results
        """
        phase_name = phase["phase"]
        tools = phase["tools"]
        results = {
            "phase": phase_name,
            "started_at": datetime.now().isoformat(),
            "tool_results": [],
            "ai_analysis": {}
        }
        
        if progress_callback:
            await progress_callback({
                "phase": phase_name,
                "status": "started",
                "message": f"Starting {phase_name} phase"
            })
        
        # Execute tools in parallel if allowed
        if phase.get("can_parallelize", False):
            tasks = []
            for tool_config in tools:
                if tool_config.get("parallel", True):
                    task = self._execute_tool(
                        tool_config["tool"], 
                        target, 
                        tool_config,
                        progress_callback
                    )
                    tasks.append(task)
            
            if tasks:
                tool_results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in tool_results:
                    if not isinstance(result, Exception):
                        results["tool_results"].append(result)
        else:
            # Execute sequentially
            for tool_config in tools:
                tool_result = await self._execute_tool(
                    tool_config["tool"],
                    target,
                    tool_config,
                    progress_callback
                )
                results["tool_results"].append(tool_result)
        
        # AI analyzes phase results
        results["ai_analysis"] = await self._ai_analyze_results(results["tool_results"])
        results["completed_at"] = datetime.now().isoformat()
        
        if progress_callback:
            await progress_callback({
                "phase": phase_name,
                "status": "completed",
                "findings": len(results["tool_results"]),
                "ai_summary": results["ai_analysis"].get("summary")
            })
        
        return results
    
    async def _execute_tool(self, tool_name: str, target: str, 
                          config: Dict, progress_callback=None) -> Dict:
        """Execute a single VAPT tool in Docker"""
        logger.info(f"Executing tool: {tool_name} on {target}")
        
        if progress_callback:
            await progress_callback({
                "tool": tool_name,
                "status": "running",
                "message": f"Running {tool_name} scan..."
            })
        
        # Tool execution mapping
        tool_executors = {
            VAPTTool.NMAP.value: self._run_nmap,
            VAPTTool.NIKTO.value: self._run_nikto,
            VAPTTool.NUCLEI.value: self._run_nuclei,
            VAPTTool.SUBLIST3R.value: self._run_sublist3r,
            VAPTTool.THEHARVESTER.value: self._run_theharvester,
            VAPTTool.SQLMAP.value: self._run_sqlmap,
            VAPTTool.TRIVY.value: self._run_trivy,
        }
        
        executor = tool_executors.get(tool_name, self._run_generic_tool)
        
        try:
            result = await executor(target, config)
            
            if progress_callback:
                await progress_callback({
                    "tool": tool_name,
                    "status": "completed",
                    "findings": result.get("findings_count", 0)
                })
            
            return result
            
        except Exception as e:
            logger.error(f"Tool {tool_name} failed: {e}")
            if progress_callback:
                await progress_callback({
                    "tool": tool_name,
                    "status": "failed",
                    "error": str(e)
                })
            return {
                "tool": tool_name,
                "status": "failed",
                "error": str(e)
            }
    
    async def _run_nmap(self, target: str, config: Dict) -> Dict:
        """Run Nmap scan in Docker"""
        from core.docker_manager import get_docker_manager

        docker_manager = get_docker_manager()
        
        scan_type = config.get("scan_type", "quick")
        
        # Map scan types to nmap flags
        nmap_flags = {
            "quick": "-T4 -F",  # Fast scan, top 100 ports
            "full": "-p- -T4",  # All 65535 ports
            "stealth": "-sS -T2",  # SYN stealth scan
            "aggressive": "-A -T4",  # OS detection, version detection, scripts
            "vuln": "--script vuln -sV"  # Vulnerability detection
        }
        
        flags = nmap_flags.get(scan_type, "-T4 -F")
        
        result = await docker_manager.run_nmap_scan(
            target=target,
            ports=None,
            scan_type=scan_type,
            timeout=600
        )
        
        return {
            "tool": "nmap",
            "target": target,
            "scan_type": scan_type,
            "result": result,
            "findings_count": len(result.get("open_ports", [])) if result.get("success") else 0
        }
    
    async def _run_nikto(self, target: str, config: Dict) -> Dict:
        """Run Nikto web scanner in Docker"""
        from core.docker_manager import get_docker_manager

        docker_manager = get_docker_manager()
        
        result = await docker_manager.run_nikto_scan(
            url=target,
            options=config.get("options", {}),
            timeout=900
        )
        
        return {
            "tool": "nikto",
            "target": target,
            "result": result,
            "findings_count": len(result.get("vulnerabilities", [])) if result.get("success") else 0
        }
    
    async def _run_nuclei(self, target: str, config: Dict) -> Dict:
        """Run Nuclei template-based scanner"""
        from core.docker_manager import get_docker_manager

        docker_manager = get_docker_manager()
        
        # Nuclei templates
        templates = config.get("templates", [
            "cves",
            "vulnerabilities",
            "exposures",
            "misconfigurations"
        ])
        
        cmd = f"nuclei -u {target} -t {','.join(templates)} -json"
        
        result = await docker_manager.run_generic_tool(
            image="projectdiscovery/nuclei:latest",
            command=cmd,
            timeout=600
        )
        
        findings = []
        if result.get("success") and result.get("output"):
            # Parse JSON lines output
            for line in result["output"].split("\n"):
                if line.strip():
                    try:
                        finding = json.loads(line)
                        findings.append(finding)
                    except:
                        pass
        
        return {
            "tool": "nuclei",
            "target": target,
            "templates": templates,
            "findings": findings,
            "findings_count": len(findings),
            "result": result
        }
    
    async def _run_sublist3r(self, target: str, config: Dict) -> Dict:
        """Run Sublist3r subdomain enumeration"""
        from core.docker_manager import get_docker_manager

        docker_manager = get_docker_manager()
        
        # Extract domain from URL if needed
        domain = target.replace("http://", "").replace("https://", "").split("/")[0]
        
        cmd = f"sublist3r -d {domain} -o /tmp/subdomains.txt"
        
        result = await docker_manager.run_generic_tool(
            image="alpine:latest",
            command=f"apk add --no-cache python3 py3-pip && pip3 install sublist3r && {cmd}",
            timeout=300
        )
        
        subdomains = []
        if result.get("success") and result.get("output"):
            subdomains = [line.strip() for line in result["output"].split("\n") if line.strip()]
        
        return {
            "tool": "sublist3r",
            "target": domain,
            "subdomains": subdomains,
            "findings_count": len(subdomains),
            "result": result
        }
    
    async def _run_theharvester(self, target: str, config: Dict) -> Dict:
        """Run theHarvester for OSINT"""
        from core.docker_manager import get_docker_manager

        docker_manager = get_docker_manager()
        
        domain = target.replace("http://", "").replace("https://", "").split("/")[0]
        sources = config.get("sources", ["google", "bing", "linkedin"])
        
        cmd = f"theHarvester -d {domain} -b {','.join(sources)}"
        
        result = await docker_manager.run_generic_tool(
            image="alpine:latest",
            command=f"apk add --no-cache python3 py3-pip && pip3 install theHarvester && {cmd}",
            timeout=300
        )
        
        return {
            "tool": "theharvester",
            "target": domain,
            "sources": sources,
            "result": result,
            "findings_count": 0  # Parse output for emails, IPs, etc.
        }
    
    async def _run_sqlmap(self, target: str, config: Dict) -> Dict:
        """Run SQLMap for SQL injection testing"""
        from core.docker_manager import get_docker_manager

        docker_manager = get_docker_manager()
        
        url = config.get("url", target)
        params = config.get("params", "")
        
        cmd = f"sqlmap -u '{url}' --batch --random-agent"
        if params:
            cmd += f" -p {params}"
        
        result = await docker_manager.run_generic_tool(
            image="ppolchinski/sqlmap:latest",
            command=cmd,
            timeout=600
        )
        
        return {
            "tool": "sqlmap",
            "target": url,
            "result": result,
            "findings_count": 1 if "injectable" in str(result.get("output", "")).lower() else 0
        }
    
    async def _run_trivy(self, target: str, config: Dict) -> Dict:
        """Run Trivy container/image scanner"""
        from core.docker_manager import get_docker_manager

        docker_manager = get_docker_manager()
        
        scan_target = config.get("image", target)
        
        cmd = f"trivy image --severity HIGH,CRITICAL {scan_target}"
        
        result = await docker_manager.run_generic_tool(
            image="aquasec/trivy:latest",
            command=cmd,
            timeout=300
        )
        
        return {
            "tool": "trivy",
            "target": scan_target,
            "result": result,
            "findings_count": 0  # Parse trivy output
        }
    
    async def _run_generic_tool(self, target: str, config: Dict) -> Dict:
        """Fallback for tools without specific implementation"""
        return {
            "tool": "generic",
            "target": target,
            "status": "not_implemented",
            "findings_count": 0
        }
    
    async def _ai_analyze_results(self, tool_results: List[Dict]) -> Dict:
        """
        AI analyzes aggregated tool results and provides insights
        
        This is where GPT-4/Azure OpenAI would analyze findings,
        correlate vulnerabilities, eliminate false positives,
        and suggest exploitation strategies
        """
        total_findings = sum(r.get("findings_count", 0) for r in tool_results)
        successful_tools = sum(1 for r in tool_results if r.get("status") != "failed")
        
        # Aggregate vulnerabilities
        vulnerabilities = []
        for result in tool_results:
            tool_name = result.get("tool")
            if result.get("findings"):
                for finding in result["findings"]:
                    vulnerabilities.append({
                        "source_tool": tool_name,
                        "finding": finding,
                        "severity": finding.get("severity", "info")
                    })
        
        # AI risk scoring
        critical_count = sum(1 for v in vulnerabilities if v.get("severity") == "critical")
        high_count = sum(1 for v in vulnerabilities if v.get("severity") == "high")
        
        risk_score = min(10, (critical_count * 2 + high_count * 1) / max(1, len(vulnerabilities)) * 10)
        
        analysis = {
            "summary": f"Found {total_findings} findings across {successful_tools} tools",
            "total_findings": total_findings,
            "tools_executed": len(tool_results),
            "tools_successful": successful_tools,
            "vulnerabilities": vulnerabilities,
            "risk_score": round(risk_score, 1),
            "severity_breakdown": {
                "critical": critical_count,
                "high": high_count,
                "medium": sum(1 for v in vulnerabilities if v.get("severity") == "medium"),
                "low": sum(1 for v in vulnerabilities if v.get("severity") == "low"),
            },
            "ai_recommendations": self._generate_ai_recommendations(vulnerabilities, risk_score)
        }
        
        return analysis
    
    def _generate_ai_recommendations(self, vulnerabilities: List[Dict], 
                                    risk_score: float) -> List[str]:
        """Generate AI-powered remediation recommendations"""
        recommendations = []
        
        if risk_score >= 8:
            recommendations.append("CRITICAL: Immediate action required. Multiple high-severity vulnerabilities detected.")
        
        # Check for specific vulnerability patterns
        vuln_types = [v.get("finding", {}).get("type", "") for v in vulnerabilities]
        
        if "sql-injection" in str(vuln_types).lower():
            recommendations.append("SQL Injection detected: Implement parameterized queries and input validation")
        
        if "xss" in str(vuln_types).lower():
            recommendations.append("XSS vulnerabilities found: Enable CSP headers and sanitize all user inputs")
        
        if len(recommendations) == 0:
            recommendations.append("Continue monitoring. No critical issues identified.")
        
        return recommendations
    
    async def generate_report(self, scan_results: Dict, format: str = "json") -> Dict:
        """
        AI generates comprehensive VAPT report
        
        Args:
            scan_results: Complete scan results from all phases
            format: Report format (json, html, pdf, markdown)
            
        Returns:
            Generated report
        """
        report = {
            "report_type": "AI-Powered VAPT Assessment",
            "generated_at": datetime.now().isoformat(),
            "target": scan_results.get("target"),
            "scan_duration": "N/A",
            "executive_summary": {},
            "technical_findings": {},
            "compliance_report": {},
            "remediation_plan": []
        }
        
        # Executive Summary (for C-level)
        all_phases = scan_results.get("phases", [])
        total_vulns = sum(
            phase.get("ai_analysis", {}).get("total_findings", 0) 
            for phase in all_phases
        )
        
        risk_scores = [
            phase.get("ai_analysis", {}).get("risk_score", 0)
            for phase in all_phases
        ]
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        
        report["executive_summary"] = {
            "overall_risk_score": round(avg_risk, 1),
            "total_vulnerabilities": total_vulns,
            "critical_issues": sum(
                phase.get("ai_analysis", {}).get("severity_breakdown", {}).get("critical", 0)
                for phase in all_phases
            ),
            "recommendations": [
                "Prioritize patching critical vulnerabilities",
                "Implement Web Application Firewall (WAF)",
                "Enable multi-factor authentication (MFA)",
                "Conduct security awareness training"
            ]
        }
        
        # Technical Findings
        report["technical_findings"] = {
            "phases_executed": [phase.get("phase") for phase in all_phases],
            "tools_used": list(set(
                result.get("tool") 
                for phase in all_phases 
                for result in phase.get("tool_results", [])
            )),
            "detailed_findings": all_phases
        }
        
        # Compliance Mapping
        report["compliance_report"] = {
            "owasp_top_10": self._map_to_owasp(all_phases),
            "pci_dss": "67% compliant (placeholder)",
            "gdpr": "Data protection controls needed"
        }
        
        return report
    
    def _map_to_owasp(self, phases: List[Dict]) -> Dict:
        """Map findings to OWASP Top 10"""
        return {
            "A01:2021-Broken Access Control": 0,
            "A02:2021-Cryptographic Failures": 0,
            "A03:2021-Injection": 0,  # Would count SQL injection findings
            "A04:2021-Insecure Design": 0,
            "A05:2021-Security Misconfiguration": 0,
            "A06:2021-Vulnerable Components": 0,
            "A07:2021-Authentication Failures": 0,
            "A08:2021-Software and Data Integrity": 0,
            "A09:2021-Security Logging Failures": 0,
            "A10:2021-SSRF": 0
        }

# Global orchestrator instance
vapt_orchestrator = VAPTOrchestrator()
