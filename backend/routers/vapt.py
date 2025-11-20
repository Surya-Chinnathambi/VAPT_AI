"""
AI-Powered VAPT Router with Real-Time WebSocket Updates
Orchestrates complete VAPT workflow with live progress streaming
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List, Dict
import asyncio
import json
import logging
from datetime import datetime

from services.vapt_orchestrator import vapt_orchestrator, VAPTPhase
from routers.auth import verify_token
from database.connection import create_scan, update_scan_status

router = APIRouter()
logger = logging.getLogger(__name__)

class VAPTScanRequest(BaseModel):
    target: str
    scope: Optional[Dict] = {}
    phases: Optional[List[str]] = ["reconnaissance", "scanning"]
    deep_scan: bool = False
    include_exploitation: bool = False

class ConnectionManager:
    """Manages WebSocket connections for real-time updates"""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
    
    async def connect(self, scan_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[scan_id] = websocket
        logger.info(f"WebSocket connected for scan {scan_id}")
    
    def disconnect(self, scan_id: str):
        if scan_id in self.active_connections:
            del self.active_connections[scan_id]
            logger.info(f"WebSocket disconnected for scan {scan_id}")
    
    async def send_update(self, scan_id: str, message: dict):
        """Send real-time update to connected client"""
        if scan_id in self.active_connections:
            try:
                await self.active_connections[scan_id].send_json(message)
            except Exception as e:
                logger.error(f"Failed to send update for scan {scan_id}: {e}")
                self.disconnect(scan_id)

connection_manager = ConnectionManager()

@router.post("/vapt/start")
async def start_vapt_scan(
    scan_request: VAPTScanRequest,
    background_tasks: BackgroundTasks,
    user_data: dict = Depends(verify_token)
):
    """
    Start comprehensive AI-powered VAPT scan
    
    **Features:**
    - AI analyzes target and creates optimal testing plan
    - Executes multiple tools in parallel
    - Real-time progress via WebSocket
    - AI-generated reports
    
    **Example:**
    ```json
    {
        "target": "http://testphp.vulnweb.com",
        "phases": ["reconnaissance", "scanning"],
        "deep_scan": false,
        "include_exploitation": false
    }
    ```
    """
    try:
        # Create scan record
        scan = create_scan(
            user_data['user_id'],
            scan_request.target,
            scan_type='vapt_full',
            tool='ai_orchestrator'
        )
        
        scan_id = str(scan['id'])
        
        # Queue background VAPT scan
        background_tasks.add_task(
            execute_vapt_scan,
            scan_id,
            scan_request.target,
            scan_request.scope,
            scan_request.phases,
            scan_request.deep_scan,
            scan_request.include_exploitation
        )
        
        return {
            "success": True,
            "scan_id": scan_id,
            "message": "AI-Powered VAPT scan initiated",
            "websocket_url": f"ws://localhost:8000/api/vapt/stream/{scan_id}",
            "estimated_duration": "15-120 minutes (depends on scope)"
        }
        
    except Exception as e:
        logger.error(f"Failed to start VAPT scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.websocket("/vapt/stream/{scan_id}")
async def vapt_realtime_stream(websocket: WebSocket, scan_id: str):
    """
    WebSocket endpoint for real-time VAPT scan updates
    
    Streams live progress including:
    - Phase transitions
    - Tool execution status
    - Vulnerability discoveries
    - AI analysis results
    """
    await connection_manager.connect(scan_id, websocket)
    
    try:
        # Keep connection alive and wait for scan completion
        while True:
            # Send periodic heartbeat
            await asyncio.sleep(5)
            await websocket.send_json({
                "type": "heartbeat",
                "timestamp": datetime.now().isoformat()
            })
            
    except WebSocketDisconnect:
        connection_manager.disconnect(scan_id)
        logger.info(f"Client disconnected from scan {scan_id}")
    except Exception as e:
        logger.error(f"WebSocket error for scan {scan_id}: {e}")
        connection_manager.disconnect(scan_id)

async def execute_vapt_scan(
    scan_id: str,
    target: str,
    scope: Dict,
    phases: List[str],
    deep_scan: bool,
    include_exploitation: bool
):
    """
    Execute complete VAPT scan with AI orchestration
    
    Args:
        scan_id: Database scan ID
        target: Target to test
        scope: Testing scope
        phases: Phases to execute
        deep_scan: Enable deep/comprehensive scanning
        include_exploitation: Include exploitation phase
    """
    logger.info(f"Starting VAPT scan {scan_id} for target {target}")
    
    async def send_progress(message: dict):
        """Send progress update via WebSocket"""
        try:
            message["scan_id"] = scan_id
            message["timestamp"] = datetime.now().isoformat()
            await connection_manager.send_update(scan_id, message)
        except Exception as e:
            logger.error(f"Failed to send progress update: {e}")
    
    try:
        # Send initial status
        await send_progress({
            "type": "scan_started",
            "target": target,
            "message": "AI analyzing target and creating testing plan..."
        })
        
        # Phase 1: AI analyzes target and creates plan
        await send_progress({
            "type": "phase",
            "phase": "planning",
            "message": "AI Decision Engine analyzing target..."
        })
        
        testing_plan = await vapt_orchestrator.analyze_target(target, scope)
        
        await send_progress({
            "type": "plan_generated",
            "plan": testing_plan,
            "message": f"AI generated testing plan with {len(testing_plan['phases'])} phases"
        })
        
        # Execute each phase
        all_results = {
            "target": target,
            "scan_id": scan_id,
            "started_at": datetime.now().isoformat(),
            "phases": []
        }
        
        for phase_config in testing_plan["phases"]:
            phase_name = phase_config["phase"]
            
            # Skip phases not in request
            if phase_name not in phases:
                continue
            
            # Skip exploitation unless explicitly enabled
            if phase_name == "exploitation" and not include_exploitation:
                await send_progress({
                    "type": "phase_skipped",
                    "phase": phase_name,
                    "reason": "Exploitation not enabled (safe mode)"
                })
                continue
            
            await send_progress({
                "type": "phase_started",
                "phase": phase_name,
                "tools": len(phase_config.get("tools", [])),
                "message": f"Starting {phase_name} phase..."
            })
            
            # Execute phase with real-time callbacks
            phase_results = await vapt_orchestrator.execute_phase(
                phase_config,
                target,
                progress_callback=send_progress
            )
            
            all_results["phases"].append(phase_results)
            
            # Send AI analysis of phase
            await send_progress({
                "type": "phase_completed",
                "phase": phase_name,
                "findings": phase_results.get("ai_analysis", {}).get("total_findings", 0),
                "risk_score": phase_results.get("ai_analysis", {}).get("risk_score", 0),
                "ai_analysis": phase_results.get("ai_analysis", {})
            })
        
        # AI generates comprehensive report
        await send_progress({
            "type": "generating_report",
            "message": "AI generating comprehensive VAPT report..."
        })
        
        final_report = await vapt_orchestrator.generate_report(all_results)
        
        all_results["report"] = final_report
        all_results["completed_at"] = datetime.now().isoformat()
        
        # Update database
        update_scan_status(
            scan_id=int(scan_id),
            status="completed",
            raw_output=json.dumps(all_results),
            summary=f"VAPT scan completed. Risk Score: {final_report['executive_summary']['overall_risk_score']}/10",
            vulnerabilities_found=final_report['executive_summary']['total_vulnerabilities'],
            risk_level=_calculate_risk_level(final_report['executive_summary']['overall_risk_score'])
        )
        
        # Send final results
        await send_progress({
            "type": "scan_completed",
            "message": "AI-Powered VAPT scan completed successfully",
            "executive_summary": final_report["executive_summary"],
            "total_phases": len(all_results["phases"]),
            "total_vulnerabilities": final_report['executive_summary']['total_vulnerabilities'],
            "risk_score": final_report['executive_summary']['overall_risk_score'],
            "report_available": True
        })
        
    except Exception as e:
        logger.error(f"VAPT scan {scan_id} failed: {e}", exc_info=True)
        
        update_scan_status(
            scan_id=int(scan_id),
            status="failed",
            error_message=str(e)
        )
        
        await send_progress({
            "type": "scan_failed",
            "error": str(e),
            "message": "VAPT scan encountered an error"
        })

def _calculate_risk_level(risk_score: float) -> str:
    """Convert risk score to risk level"""
    if risk_score >= 8:
        return "critical"
    elif risk_score >= 6:
        return "high"
    elif risk_score >= 4:
        return "medium"
    else:
        return "low"

@router.get("/vapt/report/{scan_id}")
async def get_vapt_report(
    scan_id: int,
    format: str = "json",
    user_data: dict = Depends(verify_token)
):
    """
    Get AI-generated VAPT report
    
    **Formats:**
    - json: Structured JSON data
    - markdown: Markdown report
    - html: HTML report
    - pdf: PDF report (requires additional rendering)
    """
    from database.connection import get_scan_by_id
    
    scan = get_scan_by_id(scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Check ownership
    if scan['user_id'] != user_data['user_id'] and user_data['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Access denied")
    
    if scan['status'] != 'completed':
        raise HTTPException(status_code=400, detail=f"Scan not completed (status: {scan['status']})")
    
    # Parse results
    try:
        logger.info(f"Getting report for scan {scan_id}, status: {scan['status']}")
        logger.info(f"Raw output type: {type(scan.get('raw_output'))}")
        
        raw_output = scan.get('raw_output')
        if raw_output is None:
            logger.error("raw_output is None")
            raise HTTPException(status_code=400, detail="Scan has no results yet")
        
        if isinstance(raw_output, str):
            results = json.loads(raw_output)
        else:
            results = raw_output
            
        report = results.get('report', {})
        
        if not report:
            logger.error(f"No report in results: {results.keys() if results else 'results is None'}")
            raise HTTPException(status_code=400, detail="Report not generated yet")
        
        if format == "json":
            return report
        elif format == "markdown":
            return {"markdown": _generate_markdown_report(report)}
        elif format == "html":
            return {"html": _generate_html_report(report)}
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to generate report: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")

def _generate_markdown_report(report: Dict) -> str:
    """Generate Markdown report"""
    exec_summary = report.get("executive_summary", {})
    
    md = f"""# AI-Powered VAPT Assessment Report

**Generated:** {report.get('generated_at', 'N/A')}  
**Target:** {report.get('target', 'N/A')}

## Executive Summary

**Overall Risk Score:** {exec_summary.get('overall_risk_score', 0)}/10  
**Total Vulnerabilities:** {exec_summary.get('total_vulnerabilities', 0)}  
**Critical Issues:** {exec_summary.get('critical_issues', 0)}

### Key Recommendations:
"""
    
    for rec in exec_summary.get('recommendations', []):
        md += f"- {rec}\n"
    
    md += "\n## Technical Findings\n\n"
    
    tech_findings = report.get("technical_findings", {})
    md += f"**Phases Executed:** {', '.join(tech_findings.get('phases_executed', []))}\n\n"
    md += f"**Tools Used:** {', '.join(tech_findings.get('tools_used', []))}\n\n"
    
    md += "## Compliance Report\n\n"
    compliance = report.get("compliance_report", {})
    for standard, status in compliance.items():
        md += f"- **{standard}:** {status}\n"
    
    return md

def _generate_html_report(report: Dict) -> str:
    """Generate HTML report"""
    exec_summary = report.get("executive_summary", {})
    risk_score = exec_summary.get('overall_risk_score', 0)
    
    # Risk color coding
    if risk_score >= 8:
        risk_color = "#dc3545"  # red
    elif risk_score >= 6:
        risk_color = "#fd7e14"  # orange
    elif risk_score >= 4:
        risk_color = "#ffc107"  # yellow
    else:
        risk_color = "#28a745"  # green
    
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>VAPT Report - {report.get('target', 'N/A')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .risk-score {{ font-size: 48px; font-weight: bold; color: {risk_color}; text-align: center; padding: 20px; }}
        .metric {{ display: inline-block; margin: 10px 20px; padding: 15px; background: #f8f9fa; border-radius: 5px; }}
        .metric-value {{ font-size: 32px; font-weight: bold; color: #007bff; }}
        .metric-label {{ font-size: 14px; color: #666; }}
        ul {{ line-height: 1.8; }}
        .critical {{ color: #dc3545; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ AI-Powered VAPT Assessment Report</h1>
        <p><strong>Generated:</strong> {report.get('generated_at', 'N/A')}</p>
        <p><strong>Target:</strong> {report.get('target', 'N/A')}</p>
        
        <h2>Executive Summary</h2>
        <div class="risk-score">{risk_score}/10</div>
        <div style="text-align: center;">
            <div class="metric">
                <div class="metric-value">{exec_summary.get('total_vulnerabilities', 0)}</div>
                <div class="metric-label">Total Vulnerabilities</div>
            </div>
            <div class="metric">
                <div class="metric-value critical">{exec_summary.get('critical_issues', 0)}</div>
                <div class="metric-label">Critical Issues</div>
            </div>
        </div>
        
        <h2>Key Recommendations</h2>
        <ul>
"""
    
    for rec in exec_summary.get('recommendations', []):
        html += f"            <li>{rec}</li>\n"
    
    html += """
        </ul>
        
        <h2>Compliance Status</h2>
        <ul>
"""
    
    compliance = report.get("compliance_report", {})
    for standard, status in compliance.items():
        html += f"            <li><strong>{standard}:</strong> {status}</li>\n"
    
    html += """
        </ul>
    </div>
</body>
</html>
"""
    
    return html

@router.get("/vapt/tools")
async def list_available_tools():
    """List all available VAPT tools and their capabilities"""
    from services.vapt_orchestrator import VAPTTool
    
    tools = {
        "reconnaissance": [
            {
                "name": VAPTTool.NMAP.value,
                "description": "Network discovery and port scanning",
                "category": "Network",
                "docker_image": "instrumentisto/nmap"
            },
            {
                "name": VAPTTool.SUBLIST3R.value,
                "description": "Subdomain enumeration",
                "category": "OSINT",
                "docker_image": "alpine + sublist3r"
            },
            {
                "name": VAPTTool.THEHARVESTER.value,
                "description": "Email, subdomain, employee discovery",
                "category": "OSINT",
                "docker_image": "alpine + theHarvester"
            },
            {
                "name": VAPTTool.SHODAN.value,
                "description": "Internet-exposed asset discovery",
                "category": "OSINT",
                "docker_image": "alpine + shodan-cli"
            }
        ],
        "web_scanning": [
            {
                "name": VAPTTool.NIKTO.value,
                "description": "Web server vulnerability scanner",
                "category": "Web",
                "docker_image": "sullo/nikto"
            },
            {
                "name": VAPTTool.NUCLEI.value,
                "description": "Template-based vulnerability scanner (5000+ templates)",
                "category": "Web",
                "docker_image": "projectdiscovery/nuclei"
            },
            {
                "name": VAPTTool.SQLMAP.value,
                "description": "SQL injection detection and exploitation",
                "category": "Web",
                "docker_image": "ppolchinski/sqlmap"
            },
            {
                "name": VAPTTool.ZAP.value,
                "description": "OWASP ZAP web application scanner",
                "category": "Web",
                "docker_image": "owasp/zap2docker-stable"
            }
        ],
        "container_security": [
            {
                "name": VAPTTool.TRIVY.value,
                "description": "Container and image vulnerability scanner",
                "category": "Container",
                "docker_image": "aquasec/trivy"
            }
        ]
    }
    
    return {
        "total_tools": sum(len(tools[cat]) for cat in tools),
        "categories": tools,
        "ai_orchestrated": True,
        "parallel_execution": True
    }
