"""
Real-Time VAPT Workflow Manager
Orchestrates complete real-time security assessment with WebSocket updates
"""
import asyncio
import json
import logging
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
from enum import Enum

from core.enhanced_docker_manager import get_enhanced_docker_manager
from core.realtime_tool_executor import RealtimeToolExecutor
from core.ai_security_prompts import get_system_prompt, calculate_risk_score
from services.ai_chat_service import get_chat_service

logger = logging.getLogger(__name__)


class VAPTPhase(str, Enum):
    """VAPT workflow phases"""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    ANALYSIS = "analysis"
    REPORTING = "reporting"


class RealtimeVAPTWorkflow:
    """
    Complete real-time VAPT workflow with live updates
    Implements the full 88+ tools orchestration
    """
    
    def __init__(self, progress_callback: Optional[Callable] = None):
        self.docker_manager = get_enhanced_docker_manager()
        self.tool_executor = RealtimeToolExecutor()
        self.chat_service = get_chat_service()
        self.progress_callback = progress_callback
        
        # Workflow state
        self.current_phase = None
        self.findings = []
        self.scan_metadata = {
            "start_time": None,
            "end_time": None,
            "phases_completed": [],
            "tools_executed": [],
            "total_findings": 0
        }
    
    async def execute_full_vapt(
        self,
        target: str,
        intensity: str = "standard",
        phases: List[str] = None
    ) -> Dict[str, Any]:
        """
        Execute complete VAPT workflow with real-time updates
        
        Args:
            target: Target URL/IP/domain
            intensity: quick/standard/full
            phases: List of phases to execute (default: all)
        
        Returns:
            Complete VAPT results with findings, risk scores, recommendations
        """
        self.scan_metadata["start_time"] = datetime.now()
        
        if phases is None:
            phases = [
                VAPTPhase.RECONNAISSANCE,
                VAPTPhase.SCANNING,
                VAPTPhase.ANALYSIS,
                VAPTPhase.REPORTING
            ]
        
        await self._send_progress({
            "type": "workflow_started",
            "target": target,
            "intensity": intensity,
            "phases": phases,
            "timestamp": datetime.now().isoformat()
        })
        
        results = {}
        
        try:
            # Phase 1: Reconnaissance
            if VAPTPhase.RECONNAISSANCE in phases:
                recon_results = await self._execute_reconnaissance(target, intensity)
                results["reconnaissance"] = recon_results
                self.scan_metadata["phases_completed"].append("reconnaissance")
            
            # Phase 2: Scanning
            if VAPTPhase.SCANNING in phases:
                scan_results = await self._execute_scanning(target, intensity)
                results["scanning"] = scan_results
                self.scan_metadata["phases_completed"].append("scanning")
            
            # Phase 3: Analysis
            if VAPTPhase.ANALYSIS in phases:
                analysis_results = await self._execute_analysis(results)
                results["analysis"] = analysis_results
                self.scan_metadata["phases_completed"].append("analysis")
            
            # Phase 4: Reporting
            if VAPTPhase.REPORTING in phases:
                report = await self._generate_report(results, target)
                results["report"] = report
                self.scan_metadata["phases_completed"].append("reporting")
            
            self.scan_metadata["end_time"] = datetime.now()
            duration = (self.scan_metadata["end_time"] - self.scan_metadata["start_time"]).total_seconds()
            
            await self._send_progress({
                "type": "workflow_completed",
                "duration_seconds": duration,
                "phases_completed": self.scan_metadata["phases_completed"],
                "total_findings": len(self.findings),
                "timestamp": datetime.now().isoformat()
            })
            
            return {
                "success": True,
                "target": target,
                "intensity": intensity,
                "duration": duration,
                "metadata": self.scan_metadata,
                "findings": self.findings,
                "results": results
            }
        
        except Exception as e:
            logger.error(f"VAPT workflow error: {e}")
            await self._send_progress({
                "type": "workflow_error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            })
            return {
                "success": False,
                "error": str(e),
                "metadata": self.scan_metadata
            }
    
    async def _execute_reconnaissance(
        self,
        target: str,
        intensity: str
    ) -> Dict[str, Any]:
        """Phase 1: Passive & Active Reconnaissance"""
        self.current_phase = VAPTPhase.RECONNAISSANCE
        
        await self._send_progress({
            "type": "phase_started",
            "phase": "reconnaissance",
            "description": "Gathering intelligence about target"
        })
        
        # Reconnaissance tools
        recon_tools = {
            "quick": ["nmap"],
            "standard": ["nmap", "sublist3r"],
            "full": ["nmap", "sublist3r", "amass", "dnsenum"]
        }.get(intensity, ["nmap"])
        
        tasks = []
        for tool in recon_tools:
            if tool == "nmap":
                tasks.append({
                    "tool_name": "nmap",
                    "target": target,
                    "scan_type": "quick" if intensity == "quick" else "standard"
                })
            elif tool == "sublist3r":
                tasks.append({
                    "tool_name": "sublist3r",
                    "target": target,
                    "scan_type": intensity
                })
            elif tool == "amass":
                tasks.append({
                    "tool_name": "amass",
                    "target": target,
                    "scan_type": intensity
                })
        
        # Execute tools in parallel
        results = await self._execute_tools_parallel(tasks)
        
        # Parse reconnaissance data
        recon_data = {
            "tools_executed": list(results.keys()),
            "open_ports": [],
            "services": {},
            "subdomains": [],
            "technologies": []
        }
        
        # Extract data from results
        for tool, result in results.items():
            if result.get("success") and "parsed_results" in result:
                parsed = result["parsed_results"]
                
                if tool == "nmap":
                    recon_data["open_ports"] = parsed.get("open_ports", [])
                    recon_data["services"] = parsed.get("services", {})
                elif tool in ["sublist3r", "amass"]:
                    recon_data["subdomains"].extend(parsed.get("subdomains", []))
        
        await self._send_progress({
            "type": "phase_completed",
            "phase": "reconnaissance",
            "summary": f"Found {len(recon_data['open_ports'])} open ports, {len(recon_data['subdomains'])} subdomains"
        })
        
        return recon_data
    
    async def _execute_scanning(
        self,
        target: str,
        intensity: str
    ) -> Dict[str, Any]:
        """Phase 2: Active Vulnerability Scanning"""
        self.current_phase = VAPTPhase.SCANNING
        
        await self._send_progress({
            "type": "phase_started",
            "phase": "scanning",
            "description": "Scanning for vulnerabilities"
        })
        
        # Vulnerability scanning tools
        scan_tools = {
            "quick": ["nuclei", "nikto"],
            "standard": ["nuclei", "nikto", "wpscan", "testssl"],
            "full": ["nuclei", "nikto", "wpscan", "testssl", "sqlmap", "zaproxy"]
        }.get(intensity, ["nuclei", "nikto"])

        # For web targets (URLs), always ensure a deep web tool set
        # regardless of intensity, so apps like Juice Shop get full coverage.
        if target.startswith("http://") or target.startswith("https://"):
            core_web_tools = ["nmap", "nuclei", "nikto", "sqlmap", "zaproxy", "testssl"]
            # Merge and deduplicate while preserving order
            for t in core_web_tools:
                if t not in scan_tools:
                    scan_tools.append(t)
        
        tasks = []
        for tool in scan_tools:
            tasks.append({
                "tool_name": tool,
                "target": target,
                "scan_type": intensity
            })
        
        # Execute scans in parallel
        results = await self._execute_tools_parallel(tasks)
        
        # Collect vulnerabilities
        vulnerabilities = []
        for tool, result in results.items():
            if result.get("success"):
                findings = result.get("findings_count", 0)
                if findings > 0:
                    parsed = result.get("parsed_results", {}) or {}
                    vulnerabilities.append({
                        "tool": tool,
                        "count": findings,
                        "details": parsed
                    })

                    # Derive severities per tool from parsed output/log structure
                    severities = self._derive_severities_from_tool(tool, parsed, default_count=findings)
                    for sev in severities:
                        self.findings.append({
                            "source": tool,
                            "target": target,
                            "severity": sev,
                            "description": f"Finding from {tool} ({sev})"
                        })
        
        scan_data = {
            "tools_executed": list(results.keys()),
            "vulnerabilities": vulnerabilities,
            "total_findings": sum(v["count"] for v in vulnerabilities)
        }
        
        self.scan_metadata["total_findings"] = scan_data["total_findings"]
        
        await self._send_progress({
            "type": "phase_completed",
            "phase": "scanning",
            "summary": f"Found {scan_data['total_findings']} potential vulnerabilities"
        })
        
        return scan_data
    
    async def _execute_analysis(
        self,
        results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Phase 3: AI-Powered Analysis"""
        self.current_phase = VAPTPhase.ANALYSIS
        
        await self._send_progress({
            "type": "phase_started",
            "phase": "analysis",
            "description": "AI analyzing findings and calculating risk scores"
        })
        
        # Calculate risk scores for findings
        analyzed_findings = []
        for finding in self.findings:
            # Use AI to analyze each finding
            risk_score = calculate_risk_score(
                cvss=7.5,  # TODO: Extract from finding
                exploitability="medium",
                business_impact="high",
                public_exploit=False,
                remediation_hours=4
            )
            
            analyzed_finding = {
                **finding,
                "risk_score": risk_score,
                "severity": self._determine_severity(risk_score),
                "cvss_score": 7.5,
                "exploitability": "medium",
                "remediation_priority": self._calculate_priority(risk_score)
            }
            analyzed_findings.append(analyzed_finding)
        
        # Group by severity
        severity_breakdown = {
            "critical": len([f for f in analyzed_findings if f["severity"] == "critical"]),
            "high": len([f for f in analyzed_findings if f["severity"] == "high"]),
            "medium": len([f for f in analyzed_findings if f["severity"] == "medium"]),
            "low": len([f for f in analyzed_findings if f["severity"] == "low"]),
            "info": len([f for f in analyzed_findings if f["severity"] == "info"])
        }
        
        # AI analysis summary
        analysis_prompt = f"""Analyze these security scan results and provide:
1. Overall risk assessment
2. Top 5 critical issues
3. Recommended immediate actions

Findings: {len(analyzed_findings)} total
Breakdown: {severity_breakdown}
"""
        
        ai_summary = "Security analysis complete."  # TODO: Call AI service
        
        analysis_data = {
            "analyzed_findings": analyzed_findings,
            "severity_breakdown": severity_breakdown,
            "ai_summary": ai_summary,
            "overall_risk": self._calculate_overall_risk(severity_breakdown)
        }
        
        await self._send_progress({
            "type": "phase_completed",
            "phase": "analysis",
            "summary": f"Risk Level: {analysis_data['overall_risk']}"
        })
        
        return analysis_data
        
        # Group by severity
        severity_breakdown = {
            "critical": len([f for f in analyzed_findings if f["severity"] == "critical"]),
            "high": len([f for f in analyzed_findings if f["severity"] == "high"]),
            "medium": len([f for f in analyzed_findings if f["severity"] == "medium"]),
            "low": len([f for f in analyzed_findings if f["severity"] == "low"]),
            "info": len([f for f in analyzed_findings if f["severity"] == "info"])
        }
        
        # AI analysis summary
        analysis_prompt = f"""Analyze these security scan results and provide:
1. Overall risk assessment
2. Top 5 critical issues
3. Recommended immediate actions

Findings: {len(analyzed_findings)} total
Breakdown: {severity_breakdown}
"""
        
        ai_summary = "Security analysis complete."  # TODO: Call AI service
        
        analysis_data = {
            "analyzed_findings": analyzed_findings,
            "severity_breakdown": severity_breakdown,
            "ai_summary": ai_summary,
            "overall_risk": self._calculate_overall_risk(severity_breakdown)
        }
        
        await self._send_progress({
            "type": "phase_completed",
            "phase": "analysis",
            "summary": f"Risk Level: {analysis_data['overall_risk']}"
        })
        
        return analysis_data
    
    async def _generate_report(
        self,
        results: Dict[str, Any],
        target: str
    ) -> Dict[str, Any]:
        """Phase 4: Automated Report Generation"""
        self.current_phase = VAPTPhase.REPORTING
        
        await self._send_progress({
            "type": "phase_started",
            "phase": "reporting",
            "description": "Generating comprehensive security report"
        })
        
        analysis = results.get("analysis", {})
        
        report = {
            "report_id": f"VAPT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "target": target,
            "scan_date": datetime.now().isoformat(),
            "executive_summary": {
                "total_findings": len(self.findings),
                "severity_breakdown": analysis.get("severity_breakdown", {}),
                "overall_risk": analysis.get("overall_risk", "UNKNOWN"),
                "tools_used": self.scan_metadata.get("tools_executed", [])
            },
            "technical_details": {
                "reconnaissance": results.get("reconnaissance", {}),
                "scanning": results.get("scanning", {}),
                "analysis": analysis
            },
            "remediation_roadmap": self._generate_remediation_plan(analysis),
            "compliance_mapping": self._map_to_compliance(analysis)
        }
        
        await self._send_progress({
            "type": "phase_completed",
            "phase": "reporting",
            "summary": f"Report {report['report_id']} generated"
        })
        
        return report
    
    async def _execute_tools_parallel(
        self,
        tasks: List[Dict]
    ) -> Dict[str, Any]:
        """Execute multiple tools in parallel"""
        await self._send_progress({
            "type": "parallel_execution_started",
            "tools": [t["tool_name"] for t in tasks],
            "count": len(tasks)
        })
        
        # Execute all tools concurrently
        tool_tasks = []
        for task in tasks:
            tool_task = self.tool_executor.execute_tool_realtime(
                tool_name=task["tool_name"],
                target=task["target"],
                scan_type=task.get("scan_type", "standard"),
                progress_callback=self._send_progress
            )
            tool_tasks.append(tool_task)
        
        results_list = await asyncio.gather(*tool_tasks, return_exceptions=True)
        
        # Build results dict
        results = {}
        for idx, task in enumerate(tasks):
            tool_name = task["tool_name"]
            result = results_list[idx]
            
            if isinstance(result, Exception):
                results[tool_name] = {
                    "success": False,
                    "error": str(result)
                }
            else:
                results[tool_name] = result
                self.scan_metadata["tools_executed"].append(tool_name)
        
        return results
    
    async def _send_progress(self, data: Dict):
        """Send progress update via callback"""
        if self.progress_callback:
            try:
                await self.progress_callback(data)
            except Exception as e:
                logger.error(f"Progress callback error: {e}")
    
    def _determine_severity(self, risk_score: float) -> str:
        """Determine severity from risk score"""
        if risk_score >= 9.0:
            return "critical"
        elif risk_score >= 7.0:
            return "high"
        elif risk_score >= 4.0:
            return "medium"
        elif risk_score >= 0.1:
            return "low"
        else:
            return "info"
    
    def _calculate_priority(self, risk_score: float) -> int:
        """Calculate remediation priority (1-5, 1=highest)"""
        if risk_score >= 9.0:
            return 1
        elif risk_score >= 7.0:
            return 2
        elif risk_score >= 4.0:
            return 3
        elif risk_score >= 0.1:
            return 4
        else:
            return 5
    
    def _calculate_overall_risk(self, severity_breakdown: Dict) -> str:
        """Calculate overall risk level"""
        if severity_breakdown.get("critical", 0) > 0:
            return "CRITICAL"
        elif severity_breakdown.get("high", 0) >= 3:
            return "HIGH"
        elif severity_breakdown.get("high", 0) > 0 or severity_breakdown.get("medium", 0) >= 5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_remediation_plan(self, analysis: Dict) -> List[Dict]:
        """Generate prioritized remediation plan"""
        findings = analysis.get("analyzed_findings", [])
        
        # Sort by priority
        sorted_findings = sorted(findings, key=lambda f: f.get("remediation_priority", 5))
        
        remediation_plan = []
        for finding in sorted_findings[:10]:  # Top 10
            remediation_plan.append({
                "priority": finding.get("remediation_priority"),
                "severity": finding.get("severity"),
                "description": finding.get("description"),
                "remediation": f"Fix {finding.get('source')} issue",  # TODO: AI-generated
                "effort_hours": finding.get("remediation_hours", 4)
            })
        
        return remediation_plan
    
    def _map_to_compliance(self, analysis: Dict) -> Dict:
        """Map findings to compliance frameworks"""
        return {
            "owasp_top_10": ["A01", "A03", "A05"],  # TODO: Map actual findings
            "pci_dss": ["6.5.1", "6.5.7"],
            "hipaa": ["164.308"],
            "gdpr": ["Article 32"]
        }

    def _derive_severities_from_tool(self, tool: str, parsed: Dict[str, Any], default_count: int) -> List[str]:
        """Derive a list of severities for findings from a specific tool.

        This uses simple, explainable heuristics based on common output structures
        for nuclei, nikto, sqlmap, zaproxy, testssl, etc. If structured data is
        not available, it falls back to a conservative default.
        """
        severities: List[str] = []

        # 1) Nuclei: expect a list of issues with severity fields
        if tool == "nuclei":
            issues = parsed.get("issues") or parsed.get("results") or []
            for issue in issues:
                sev = (issue.get("severity") or "medium").lower()
                if sev not in ("critical", "high", "medium", "low"):
                    sev = "medium"
                severities.append(sev)

        # 2) Nikto: high/med/low counts
        elif tool == "nikto":
            counts = parsed.get("severity_counts") or {}
            severities.extend(["high"] * int(counts.get("high", 0)))
            severities.extend(["medium"] * int(counts.get("medium", 0)))
            severities.extend(["low"] * int(counts.get("low", 0)))

        # 3) sqlmap: treat confirmed injections as high/critical depending on flags
        elif tool == "sqlmap":
            vulns = parsed.get("vulnerabilities") or []
            for v in vulns:
                risk = (v.get("risk") or "").lower()
                if risk in ("3", "high", "critical"):
                    severities.append("critical")
                elif risk in ("2", "medium"):
                    severities.append("high")
                else:
                    severities.append("medium")

        # 4) zaproxy: issues with risk field
        elif tool == "zaproxy":
            alerts = parsed.get("alerts") or []
            for a in alerts:
                risk = (a.get("risk") or a.get("riskcode") or "").lower()
                if isinstance(risk, str):
                    if "high" in risk or risk == "3":
                        severities.append("high")
                    elif "medium" in risk or risk == "2":
                        severities.append("medium")
                    elif "low" in risk or risk == "1":
                        severities.append("low")

        # 5) testssl: map grade or finding categories
        elif tool == "testssl":
            grade = (parsed.get("grade") or "").upper()
            if grade in ("F", "T", "M"):
                severities.append("critical")
            elif grade in ("E", "D"):
                severities.append("high")
            elif grade in ("C",):
                severities.append("medium")
            elif grade in ("B", "A"):
                severities.append("low")

        # 6) Fallback: if we detected findings but have no structure, assign medium
        if not severities and default_count > 0:
            severities = ["medium"] * default_count

        return severities


# Global instance
_realtime_vapt = None


def get_realtime_vapt_workflow(progress_callback: Optional[Callable] = None) -> RealtimeVAPTWorkflow:
    """Get or create realtime VAPT workflow instance"""
    return RealtimeVAPTWorkflow(progress_callback=progress_callback)
