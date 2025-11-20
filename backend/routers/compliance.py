"""
Compliance API endpoints
"""
from fastapi import APIRouter, Depends, HTTPException
from typing import List
from pydantic import BaseModel
from services.compliance_engine import get_compliance_engine

router = APIRouter()

class VulnerabilityInput(BaseModel):
    type: str
    description: str
    severity: str
    port: int = None
    service: str = None

class ComplianceAssessmentRequest(BaseModel):
    vulnerabilities: List[VulnerabilityInput]
    frameworks: List[str] = None

class ComplianceMappingRequest(BaseModel):
    vulnerability: VulnerabilityInput
    frameworks: List[str] = None

@router.get("/frameworks")
async def list_frameworks():
    """List all available compliance frameworks"""
    engine = get_compliance_engine()
    return {
        "frameworks": engine.list_frameworks()
    }

@router.get("/frameworks/{framework_code}")
async def get_framework_details(framework_code: str):
    """Get details about a specific framework"""
    engine = get_compliance_engine()
    framework = engine.get_framework_info(framework_code)
    
    if not framework:
        raise HTTPException(status_code=404, detail="Framework not found")
    
    return framework

@router.post("/map")
async def map_vulnerability(request: ComplianceMappingRequest):
    """Map a single vulnerability to compliance requirements"""
    engine = get_compliance_engine()
    
    vuln_dict = request.vulnerability.dict()
    mappings = engine.map_vulnerability_to_frameworks(
        vuln_dict,
        request.frameworks
    )
    
    return {
        "vulnerability": vuln_dict,
        "mappings": mappings
    }

@router.post("/assess")
async def assess_compliance(request: ComplianceAssessmentRequest):
    """Generate comprehensive compliance assessment"""
    engine = get_compliance_engine()
    
    vulnerabilities = [v.dict() for v in request.vulnerabilities]
    report = engine.generate_compliance_report(
        vulnerabilities,
        request.frameworks
    )
    
    return report
