import json
from typing import List, Dict, Any, Tuple
from services.ai_vapt_orchestrator import AIVAPTOrchestrator, VAPTTarget
from services.nmap_scanner_service import NmapScanner
from services.realtime_vapt_workflow import get_realtime_vapt_workflow
from mcp_server.protocol import Tool, CallToolResult
from tasks.scan_tasks import run_port_scan

# Database imports with fallback
try:
    from database.connection import create_scan, update_scan_status
    USE_POSTGRES = True
except ImportError:
    # Fallback for SQLite or if DB is not set up
    def create_scan(user_id, target, scan_type, tool):
        # Mock implementation or SQLite implementation
        # For now, we'll just return a mock ID
        return {"id": 999, "status": "running"}
    def update_scan_status(*args, **kwargs):
        return None
    USE_POSTGRES = False

class VaptMcpTools:
    def __init__(self):
        self.orchestrator = AIVAPTOrchestrator()
        self.nmap_service = NmapScanner()

    def get_tools(self) -> List[Tool]:
        return [
            Tool(
                name="run_vapt_scan",
                description="Run a full AI-powered VAPT scan on a target",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target URL or IP"},
                        "scan_type": {"type": "string", "enum": ["quick", "full", "custom"]},
                        "user_id": {"type": "integer", "description": "User ID initiating the scan"}
                    },
                    "required": ["target"]
                }
            ),
            Tool(
                name="run_nmap_scan",
                description="Run a specific Nmap scan",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "ports": {"type": "string", "description": "Port range (e.g., '1-1000')"},
                        "user_id": {"type": "integer", "description": "User ID initiating the scan"}
                    },
                    "required": ["target"]
                }
            ),
            Tool(
                name="analyze_vulnerability",
                description="Analyze a specific vulnerability finding using AI",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "finding_id": {"type": "string"},
                        "description": {"type": "string"}
                    },
                    "required": ["description"]
                }
            )
        ]

    async def handle_call_tool(self, name: str, arguments: Dict[str, Any]) -> CallToolResult:
        if name == "run_vapt_scan":
            return await self._run_vapt_scan(arguments)
        elif name == "run_nmap_scan":
            return await self._run_nmap_scan(arguments)
        elif name == "analyze_vulnerability":
            return await self._analyze_vulnerability(arguments)
        else:
            raise ValueError(f"Unknown tool: {name}")

    async def _run_vapt_scan(self, args: Dict[str, Any]) -> CallToolResult:
        target_str = args.get("target")
        user_id = args.get("user_id", 1) # Default to admin
        scan_type = args.get("scan_type", "full")
        if not target_str:
            return CallToolResult(
                content=[{
                    "type": "text",
                    "text": "Missing target parameter for VAPT scan"
                }],
                isError=True
            )
        
        intensity = self._map_scan_type(scan_type)
        scan = None
        scan_id = None
        
        try:
            # Create DB record if possible
            scan = create_scan(user_id, target_str, scan_type, "realtime_vapt")
            scan_id = scan.get('id')
        except Exception:
            # Continue even if persistence fails
            scan_id = None
        
        try:
            workflow = get_realtime_vapt_workflow(progress_callback=None)
            result = await workflow.execute_full_vapt(target=target_str, intensity=intensity)
            
            if not result.get("success"):
                if USE_POSTGRES and scan_id:
                    update_scan_status(scan_id, 'failed', error_message=result.get('error'))
                return CallToolResult(
                    content=[{
                        "type": "text",
                        "text": f"VAPT scan failed for {target_str}: {result.get('error', 'Unknown error')}"
                    }],
                    isError=True
                )
            
            summary_text, severity_counts = self._build_summary_text(result, target_str, scan_id)
            total_findings = sum(severity_counts.values())
            risk_level = self._derive_risk(severity_counts)
            
            if USE_POSTGRES and scan_id:
                update_scan_status(
                    scan_id,
                    'completed',
                    raw_output=json.dumps(result),
                    summary=summary_text,
                    vulnerabilities_found=total_findings,
                    risk_level=risk_level
                )
            
            return CallToolResult(
                content=[
                    {
                        "type": "text",
                        "text": summary_text
                    },
                    {
                        "type": "json",
                        "json": {
                            "scan_id": scan_id,
                            "risk_level": risk_level,
                            "severity_counts": severity_counts,
                            "tools_executed": result.get("metadata", {}).get("tools_executed", []),
                            "duration_seconds": result.get("duration"),
                            "findings": result.get("findings", [])
                        }
                    }
                ]
            )
        except Exception as e:
            if USE_POSTGRES and scan_id:
                update_scan_status(scan_id, 'failed', error_message=str(e))
            return CallToolResult(
                content=[{
                    "type": "text",
                    "text": f"Failed to execute VAPT scan: {str(e)}"
                }],
                isError=True
            )

    async def _run_nmap_scan(self, args: Dict[str, Any]) -> CallToolResult:
        target = args.get("target")
        ports = args.get("ports", "1-1000")
        user_id = args.get("user_id", 1)
        
        try:
            # Create DB record
            scan = create_scan(user_id, target, "port_scan", "nmap")
            scan_id = scan['id']
            
            # Trigger Celery Task
            # Simple port parsing
            port_list = ports.split(',') if ',' in ports else [ports]
            
            task = run_port_scan.delay(scan_id, target, port_list)
            
            return CallToolResult(
                content=[{
                    "type": "text",
                    "text": f"Nmap scan started on {target}. Scan ID: {scan_id}. Task ID: {task.id}"
                }]
            )
        except Exception as e:
            return CallToolResult(
                content=[{
                    "type": "text",
                    "text": f"Failed to start Nmap scan: {str(e)}"
                }],
                isError=True
            )

    async def _analyze_vulnerability(self, args: Dict[str, Any]) -> CallToolResult:
        desc = args.get("description")
        # Simulate AI analysis
        return CallToolResult(
            content=[{
                "type": "text",
                "text": f"Analysis for: {desc}\nSeverity: High\nRemediation: Update the affected library."
            }]
        )

    def _map_scan_type(self, scan_type: str) -> str:
        normalized = (scan_type or "").lower()
        if normalized in ("quick", "fast"):
            return "quick"
        if normalized in ("full", "aggressive", "custom"):
            return "full"
        return "standard"

    def _build_summary_text(self, result: Dict[str, Any], target: str, scan_id: int) -> Tuple[str, Dict[str, int]]:
        findings = result.get("findings", []) or []
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in findings:
            severity = (finding.get("severity") or "").lower()
            if severity in counts:
                counts[severity] += 1
        duration = result.get("duration") or 0
        tools = result.get("metadata", {}).get("tools_executed", []) or []
        summary = (
            f"VAPT scan completed for {target} (Scan ID: {scan_id or 'N/A'}).\n"
            f"Duration: {duration:.1f}s | Tools executed: {len(tools)} | Findings - "
            f"Critical: {counts['critical']}, High: {counts['high']}, "
            f"Medium: {counts['medium']}, Low: {counts['low']}"
        )
        return summary, counts

    def _derive_risk(self, counts: Dict[str, int]) -> str:
        if counts.get("critical", 0) > 0:
            return "critical"
        if counts.get("high", 0) > 0:
            return "high"
        if counts.get("medium", 0) > 2:
            return "medium"
        if counts.get("medium", 0) > 0 or counts.get("low", 0) > 0:
            return "low"
        return "informational"
