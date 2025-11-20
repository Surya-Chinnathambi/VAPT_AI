from fastapi import APIRouter, Depends
import json
from datetime import datetime, timedelta
from typing import List, Dict
from psycopg2.extras import RealDictCursor

from routers.auth import verify_token
from database.connection import get_user_scans, get_db_connection, get_user_monthly_usage

router = APIRouter()

@router.get("/stats")
async def get_dashboard_stats(user_data: dict = Depends(verify_token)):
    # Get monthly scan count
    monthly_scans = get_user_monthly_usage(user_data['user_id'])
    
    # Get total counts
    with get_db_connection() as conn:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("SELECT COUNT(*) as count FROM scans WHERE user_id = %s", 
                      (user_data['user_id'],))
        total_scans = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM reports WHERE user_id = %s", 
                      (user_data['user_id'],))
        total_reports = cursor.fetchone()['count']
        cursor.close()
    
    scan_limit = 999 if user_data['role'] == 'pro' else 5
    scans_remaining = max(0, scan_limit - monthly_scans)
    
    # Count vulnerabilities from scan results
    vulnerabilities_found = 0
    scans = get_user_scans(user_data['user_id'], limit=100)
    for scan in scans:
        try:
            vulnerabilities_found += scan.get('vulnerabilities_found', 0)
        except:
            pass
    
    return {
        "total_scans": total_scans,
        "vulnerabilities_found": vulnerabilities_found,
        "scans_remaining": scans_remaining,
        "subscription_tier": user_data['role'].capitalize(),
        "monthly_scans": monthly_scans,
        "total_reports": total_reports
    }

@router.get("/activity")
async def get_activity(user_data: dict = Depends(verify_token)):
    scans = get_user_scans(user_data['user_id'], limit=100)
    
    scan_activity = []
    for scan in scans:
        try:
            created_at = scan['created_at']
            if isinstance(created_at, str):
                date = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            else:
                date = created_at
            
            scan_activity.append({
                "date": date.date().isoformat() if hasattr(date, 'date') else str(date),
                "scan_type": scan['scan_type'],
                "target": scan['target']
            })
        except:
            continue
    
    return {"activity": scan_activity}

@router.get("/vulnerability-distribution")
async def get_vulnerability_distribution(user_data: dict = Depends(verify_token)):
    scans = get_user_scans(user_data['user_id'], limit=50)
    
    risk_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    
    for scan in scans:
        try:
            risk_level = scan.get('risk_level', 'low')
            if risk_level in risk_counts:
                risk_counts[risk_level] += 1
        except:
            continue
    
    return {"distribution": risk_counts}

def calculate_threat_level(user_id: int):
    scans = get_user_scans(user_id, limit=20)
    
    if not scans:
        return "LOW"
    
    total_risk_score = 0
    scan_count = 0
    
    for scan in scans:
        try:
            results = json.loads(scan['results'])
            
            if scan['scan_type'] == 'web_scan':
                risk_summary = results.get('risk_summary', {})
                score = (risk_summary.get('high', 0) * 3 + 
                        risk_summary.get('medium', 0) * 2 + 
                        risk_summary.get('low', 0) * 1)
                total_risk_score += score
                scan_count += 1
            elif scan['scan_type'] == 'port_scan':
                open_ports = len(results.get('open_ports', []))
                if open_ports > 15:
                    total_risk_score += 3
                elif open_ports > 8:
                    total_risk_score += 2
                else:
                    total_risk_score += 1
                scan_count += 1
        except:
            continue
    
    if scan_count == 0:
        return "LOW"
    
    avg_risk = total_risk_score / scan_count
    
    if avg_risk >= 8:
        return "CRITICAL"
    elif avg_risk >= 5:
        return "HIGH"
    elif avg_risk >= 2:
        return "MEDIUM"
    else:
        return "LOW"
