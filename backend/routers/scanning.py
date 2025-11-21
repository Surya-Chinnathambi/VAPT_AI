from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks, Request, Response
import json
import os
from typing import List, Dict, Optional
from pydantic import BaseModel

from models.scan import PortScanRequest, WebScanRequest, ScanResponse
from routers.auth import verify_token
from services.port_scanner_service import perform_port_scan
from services.web_scanner_service import perform_web_scan
from services.nmap_scanner_service import nmap_scanner
from database.connection import (
    create_scan, 
    update_scan_status, 
    get_user_scans, 
    get_scan_by_id,
    get_user_monthly_usage
)
from workers.scan_tasks import run_nmap_scan, run_web_scan, run_shodan_lookup
from core.rate_limiting import limiter, scan_limit

router = APIRouter()

class NmapScanRequest(BaseModel):
    target: str
    scan_type: str = "quick"  # quick, full, vuln, web, stealth, aggressive
    async_mode: bool = True  # Run in background by default

@router.post("/nmap", response_model=dict)
@limiter.limit("10/minute")  # Rate limit: 10 scans per minute
async def nmap_scan(
    request: Request,
    response: Response,
    scan_request: NmapScanRequest,
    user_data: dict = Depends(verify_token)
):
    """
    Advanced Nmap scanning with multiple scan types (Async by default):
    - quick: Fast scan (top 100 ports)
    - full: Comprehensive scan (all 65535 ports)
    - vuln: Vulnerability detection scan
    - web: Web application scan
    - stealth: Stealth SYN scan
    - aggressive: OS detection + scripts
    """
    # Check scan limits
    monthly_scans = get_user_monthly_usage(user_data['user_id'])
    max_scans = int(os.getenv('MAX_SCANS_PER_MONTH', '100'))
    limit = 999 if user_data['role'] == 'pro' else max_scans
    
    if monthly_scans >= limit:
        raise HTTPException(status_code=403, detail=f"Monthly scan limit reached ({limit} scans)")
    
    try:
        # Create scan record
        scan = create_scan(
            user_data['user_id'],
            scan_request.target,
            scan_type='nmap',
            tool='nmap'
        )
        
        # Queue background task
        if scan_request.async_mode:
            task = run_nmap_scan.delay(scan['id'], scan_request.target, scan_request.scan_type)
            
            return {
                "success": True,
                "scan_id": scan['id'],
                "task_id": task.id,
                "status": "queued",
                "message": "Scan started in background. Check status with /scan/status/{scan_id}"
            }
        else:
            # Synchronous execution (for testing)
            task_result = run_nmap_scan(scan['id'], scan_request.target, scan_request.scan_type)
            return task_result
    
    except Exception as e:
        if 'scan' in locals():
            update_scan_status(scan['id'], 'failed', error_message=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/status/{scan_id}")
async def get_scan_status(
    scan_id: int,
    user_data: dict = Depends(verify_token)
):
    """Get status of a running or completed scan"""
    try:
        scan = get_scan_by_id(scan_id)
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Check ownership
        if scan['user_id'] != user_data['user_id'] and user_data['role'] != 'admin':
            raise HTTPException(status_code=403, detail="Access denied")
        
        return {
            "scan_id": scan_id,
            "status": scan['status'],
            "target": scan['target'],
            "progress": scan.get('progress', 0),
            "vulnerabilities_found": scan.get('vulnerabilities_found'),
            "risk_level": scan.get('risk_level'),
            "summary": scan.get('summary'),
            "created_at": str(scan.get('created_at')),
            "completed_at": str(scan.get('completed_at')) if scan.get('completed_at') else None,
            "error_message": scan.get('error_message')
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/port", response_model=dict)
async def scan_ports(
    request: PortScanRequest,
    user_data: dict = Depends(verify_token)
):
    # Check scan limits
    monthly_scans = get_user_monthly_usage(user_data['user_id'])
    max_scans = int(os.getenv('MAX_SCANS_PER_MONTH', '100'))
    limit = 999 if user_data['role'] == 'pro' else max_scans
    
    if monthly_scans >= limit:
        raise HTTPException(status_code=403, detail=f"Monthly scan limit reached ({limit} scans)")
    
    try:
        # Create scan record
        scan = create_scan(
            user_id=user_data['user_id'],
            target=request.host,
            scan_type='port_scan',
            tool='nmap'
        )
        
        # Perform scan
        results = perform_port_scan(request.host, request.ports, request.scan_type)
        
        # Count vulnerabilities (open ports)
        vulnerabilities_found = len(results.get('open_ports', []))
        
        # Determine risk level
        risk_level = 'low'
        if vulnerabilities_found > 10:
            risk_level = 'high'
        elif vulnerabilities_found > 5:
            risk_level = 'medium'
        
        # Update scan with results
        update_scan_status(
            scan_id=scan['id'],
            status='completed',
            raw_output=json.dumps(results),
            summary=f"Found {vulnerabilities_found} open ports",
            vulnerabilities_found=vulnerabilities_found,
            risk_level=risk_level
        )
        
        return {
            "success": True,
            "scan_id": scan['id'],
            "results": results,
            "vulnerabilities_found": vulnerabilities_found,
            "risk_level": risk_level
        }
    except Exception as e:
        if 'scan' in locals():
            update_scan_status(scan['id'], 'failed', error_message=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/web", response_model=dict)
async def scan_web(
    request: WebScanRequest,
    user_data: dict = Depends(verify_token)
):
    # Check scan limits
    monthly_scans = get_user_monthly_usage(user_data['user_id'])
    max_scans = int(os.getenv('MAX_SCANS_PER_MONTH', '100'))
    limit = 999 if user_data['role'] == 'pro' else max_scans
    
    if monthly_scans >= limit:
        raise HTTPException(status_code=403, detail=f"Monthly scan limit reached ({limit} scans)")
    
    try:
        # Create scan record
        scan = create_scan(
            user_id=user_data['user_id'],
            target=request.url,
            scan_type='web_scan',
            tool='custom'
        )
        
        # Perform scan
        results = perform_web_scan(request.url, request.options)
        
        # Get vulnerabilities count from results
        risk_summary = results.get('risk_summary', {})
        vulnerabilities_found = risk_summary.get('high', 0) + risk_summary.get('medium', 0)
        
        # Determine risk level
        risk_level = 'low'
        if risk_summary.get('high', 0) > 0:
            risk_level = 'critical' if risk_summary.get('high', 0) > 3 else 'high'
        elif risk_summary.get('medium', 0) > 2:
            risk_level = 'medium'
        
        # Update scan with results
        update_scan_status(
            scan_id=scan['id'],
            status='completed',
            raw_output=json.dumps(results),
            summary=f"Found {vulnerabilities_found} vulnerabilities",
            vulnerabilities_found=vulnerabilities_found,
            risk_level=risk_level
        )
        
        return {
            "success": True,
            "scan_id": scan['id'],
            "results": results,
            "vulnerabilities_found": vulnerabilities_found,
            "risk_level": risk_level
        }
    except Exception as e:
        if 'scan' in locals():
            update_scan_status(scan['id'], 'failed', error_message=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/history", response_model=List[dict])
async def get_scan_history(
    limit: int = 20,
    offset: int = 0,
    user_data: dict = Depends(verify_token)
):
    """Get scan history for authenticated user"""
    scans = get_user_scans(user_data['user_id'], limit, offset)
    
    # Parse JSON results if present
    for scan in scans:
        if scan.get('raw_output'):
            try:
                scan['results'] = json.loads(scan['raw_output'])
            except:
                pass
    
    return scans

@router.get("/result/{scan_id}", response_model=dict)
async def get_scan_result(
    scan_id: int,
    user_data: dict = Depends(verify_token)
):
    """Get specific scan result"""
    scan = get_scan_by_id(scan_id, user_data['user_id'])
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Parse JSON results
    if scan.get('raw_output'):
        try:
            scan['results'] = json.loads(scan['raw_output'])
        except:
            pass
    
    return scan

@router.get("/stats", response_model=dict)
async def get_scan_stats(user_data: dict = Depends(verify_token)):
    """Get user's scan statistics"""
    monthly_scans = get_user_monthly_usage(user_data['user_id'])
    max_scans = int(os.getenv('MAX_SCANS_PER_MONTH', '100'))
    limit = 999 if user_data['role'] == 'pro' else max_scans
    
    return {
        "monthly_scans": monthly_scans,
        "limit": limit,
        "remaining": max(0, limit - monthly_scans),
        "role": user_data['role']
    }
