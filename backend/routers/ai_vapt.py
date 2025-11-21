"""
AI-Powered VAPT API Router
Exposes AI-driven VAPT workflow via REST API
"""
from fastapi import APIRouter, HTTPException, Depends, Request, Response
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
import logging

from routers.auth import verify_token
from services.ai_vapt_orchestrator import AIVAPTOrchestrator, VAPTTarget
from core.rate_limiting import limiter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ai-vapt", tags=["AI-VAPT"])


class VAPTScanRequest(BaseModel):
    """AI-VAPT scan request"""
    url: Optional[str] = Field(None, description="Target URL to scan")
    domain: Optional[str] = Field(None, description="Target domain")
    ip_address: Optional[str] = Field(None, description="Target IP address")
    scope: List[str] = Field(default_factory=list, description="Scan scope (subdomains, IP ranges)")
    authorization_proof: Optional[str] = Field(None, description="Authorization token/proof")
    allowed_active_scan: bool = Field(True, description="Allow active vulnerability scanning")
    
    class Config:
        json_schema_extra = {
            "example": {
                "url": "https://demo.owasp-juice.shop",
                "domain": "demo.owasp-juice.shop",
                "scope": ["*.owasp-juice.shop"],
                "authorization_proof": "written_permission_ref_12345",
                "allowed_active_scan": True
            }
        }


class VAPTScanResponse(BaseModel):
    """AI-VAPT scan response"""
    scan_id: str
    status: str
    target: Dict[str, Any]
    automation_percentage: float
    phases_completed: List[str]
    findings_summary: Dict[str, int]
    report_url: Optional[str] = None
    message: str


@router.post("/scan", response_model=VAPTScanResponse)
@limiter.limit("3/hour")
async def start_ai_vapt_scan(
    request: Request,
    response: Response,
    scan_request: VAPTScanRequest,
    user_data: dict = Depends(verify_token)
):
    """
    Start AI-powered VAPT workflow
    
    **Features:**
    - 40-50% overall automation
    - 7-phase intelligent workflow
    - AI-driven decision making
    - Comprehensive reporting
    
    **Phases:**
    1. Validation (70% automated)
    2. Passive Recon (100% automated)
    3. Active Scanning (80-90% automated)
    4. AI Analysis (60-70% automated)
    5. Exploitation Suggestions (10-40% automated)
    6. Remediation Plans (90% automated)
    7. Report Generation (90% automated)
    """
    try:
        logger.info(f"User {user_data['username']} starting AI-VAPT scan")
        
        # Convert request to VAPTTarget
        target = VAPTTarget(
            url=scan_request.url,
            domain=scan_request.domain,
            ip_address=scan_request.ip_address,
            scope=scan_request.scope,
            authorization_proof=scan_request.authorization_proof,
            allowed_active_scan=scan_request.allowed_active_scan
        )
        
        # Execute AI-VAPT workflow
        orchestrator = AIVAPTOrchestrator()
        workflow_result = await orchestrator.execute_vapt_workflow(target)
        
        if not workflow_result['success']:
            raise HTTPException(
                status_code=400,
                detail=f"VAPT workflow failed: {workflow_result.get('error')}"
            )
        
        # Generate scan ID
        scan_id = f"VAPT-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        return VAPTScanResponse(
            scan_id=scan_id,
            status="completed",
            target=workflow_result['target'],
            automation_percentage=workflow_result['automation_percentage'],
            phases_completed=workflow_result['phases_completed'],
            findings_summary=workflow_result['severity_breakdown'],
            report_url=f"/api/ai-vapt/reports/{scan_id}",
            message=f"AI-VAPT scan completed successfully. {workflow_result['findings_count']} vulnerabilities identified."
        )
        
    except Exception as e:
        logger.error(f"AI-VAPT scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scan/{scan_id}")
async def get_scan_status(
    scan_id: str,
    user_data: dict = Depends(verify_token)
):
    """Get AI-VAPT scan status and results"""
    # TODO: Implement scan status retrieval from database
    return {
        "scan_id": scan_id,
        "status": "completed",
        "message": "Scan status retrieval not yet implemented"
    }


@router.get("/reports/{scan_id}")
async def get_scan_report(
    scan_id: str,
    format: str = "json",
    user_data: dict = Depends(verify_token)
):
    """
    Get comprehensive VAPT report
    
    **Formats:**
    - json: Structured JSON report
    - pdf: PDF report (coming soon)
    - html: HTML report (coming soon)
    """
    # TODO: Implement report retrieval
    return {
        "scan_id": scan_id,
        "format": format,
        "message": "Report retrieval not yet implemented"
    }


@router.get("/capabilities")
async def get_ai_vapt_capabilities():
    """Get AI-VAPT system capabilities and automation levels"""
    return {
        "system_version": "1.0",
        "overall_automation": "40-50%",
        "phases": {
            "validation": {
                "automation_level": "70%",
                "description": "Target validation, legality checks, scope verification"
            },
            "passive_recon": {
                "automation_level": "100%",
                "description": "DNS enum, tech fingerprinting, exposure lookup, reputation analysis",
                "tools": ["DNS enumeration", "Technology detection", "Shodan-style lookup", "SSL analysis"]
            },
            "active_scanning": {
                "automation_level": "80-90%",
                "description": "Automated vulnerability scanning with intelligent tool selection",
                "tools": ["Nmap", "Nikto", "Gobuster", "TestSSL", "SQLMap", "Nuclei"]
            },
            "ai_analysis": {
                "automation_level": "60-70%",
                "description": "AI classifies vulnerabilities, filters false positives, maps to frameworks",
                "features": ["CVSS scoring", "OWASP/MITRE mapping", "False positive filtering", "Severity adjustment"]
            },
            "exploitation_suggestions": {
                "automation_level": "10-40%",
                "description": "AI suggests exploitation paths and attack chains",
                "features": ["Attack chain generation", "Payload examples", "Tool recommendations"]
            },
            "remediation": {
                "automation_level": "90%",
                "description": "Automated remediation plans with code patches and config changes",
                "features": ["Code patches", "Config changes", "Verification steps", "Priority ranking"]
            },
            "reporting": {
                "automation_level": "90%",
                "description": "Comprehensive reports with executive summary and technical details",
                "formats": ["JSON", "PDF (coming soon)", "HTML (coming soon)"]
            }
        },
        "frameworks_supported": [
            "OWASP Top 10 2021",
            "MITRE ATT&CK",
            "CWE Top 25",
            "CVE/CVSS",
            "PCI-DSS",
            "GDPR (Article 32)"
        ]
    }
