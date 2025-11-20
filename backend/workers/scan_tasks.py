"""
Scan Background Tasks
Handles asynchronous scanning operations (Nmap, Web, Shodan)
"""

from workers.celery_app import celery_app
from services.nmap_scanner_service import nmap_scanner
from services.web_scanner_service import perform_web_scan
from database.connection import create_scan, update_scan_status
import json
import requests
from datetime import datetime, timedelta

@celery_app.task(bind=True, name="workers.scan_tasks.run_nmap_scan")
def run_nmap_scan(self, scan_id: int, target: str, scan_type: str = "quick"):
    """
    Background task for Nmap scanning
    
    Args:
        scan_id: Database scan record ID
        target: Target IP/domain
        scan_type: Type of scan (quick, full, vuln, web, stealth, aggressive)
    """
    try:
        # Update status to running (removed progress parameter)
        update_scan_status(scan_id, "running")
        
        # Select scan type
        if scan_type == "quick":
            results = nmap_scanner.quick_scan(target)
        elif scan_type == "full":
            results = nmap_scanner.full_scan(target)
        elif scan_type == "vuln":
            results = nmap_scanner.vulnerability_scan(target)
        elif scan_type == "web":
            results = nmap_scanner.web_scan(target)
        elif scan_type == "stealth":
            results = nmap_scanner.stealth_scan(target)
        elif scan_type == "aggressive":
            results = nmap_scanner.aggressive_scan(target)
        else:
            results = nmap_scanner.quick_scan(target)
        
        # Calculate risk
        vulnerabilities_found = results.get("summary", {}).get("vulnerabilities_found", 0)
        if vulnerabilities_found == 0:
            vulnerabilities_found = results.get("summary", {}).get("open_ports", 0)
        
        risk_level = "low"
        if vulnerabilities_found > 15:
            risk_level = "critical"
        elif vulnerabilities_found > 10:
            risk_level = "high"
        elif vulnerabilities_found > 5:
            risk_level = "medium"
        
        # Update scan with results (removed progress parameter)
        update_scan_status(
            scan_id=scan_id,
            status="completed",
            raw_output=json.dumps(results),
            summary=f"{scan_type.upper()} scan: {vulnerabilities_found} issues found",
            vulnerabilities_found=vulnerabilities_found,
            risk_level=risk_level
        )
        
        return {
            "success": True,
            "scan_id": scan_id,
            "vulnerabilities": vulnerabilities_found,
            "risk_level": risk_level
        }
        
    except Exception as e:
        update_scan_status(
            scan_id,
            "failed",
            error_message=str(e)
        )
        raise self.retry(exc=e, countdown=60, max_retries=2)


@celery_app.task(bind=True, name="workers.scan_tasks.run_web_scan")
def run_web_scan(self, scan_id: int, url: str, options: dict = None):
    """
    Background task for web vulnerability scanning
    
    Args:
        scan_id: Database scan record ID
        url: Target URL
        options: Scan options
    """
    try:
        update_scan_status(scan_id, "running")
        
        results = perform_web_scan(url, options or {})
        
        vulnerabilities_found = len(results.get("vulnerabilities", []))
        risk_level = "low"
        
        if vulnerabilities_found > 10:
            risk_level = "critical"
        elif vulnerabilities_found > 5:
            risk_level = "high"
        elif vulnerabilities_found > 2:
            risk_level = "medium"
        
        update_scan_status(
            scan_id=scan_id,
            status="completed",
            raw_output=json.dumps(results),
            summary=f"Web scan: {vulnerabilities_found} vulnerabilities found",
            vulnerabilities_found=vulnerabilities_found,
            risk_level=risk_level
        )
        
        return {
            "success": True,
            "scan_id": scan_id,
            "vulnerabilities": vulnerabilities_found
        }
        
    except Exception as e:
        update_scan_status(scan_id, "failed", error_message=str(e))
        raise self.retry(exc=e, countdown=60, max_retries=2)


@celery_app.task(bind=True, name="workers.scan_tasks.run_shodan_lookup")
def run_shodan_lookup(self, scan_id: int, query: str):
    """
    Background task for Shodan intelligence gathering
    
    Args:
        scan_id: Database scan record ID
        query: Target IP/domain
    """
    try:
        import os
        from urllib.parse import urlparse
        
        update_scan_status(scan_id, "running")
        
        # Parse URL if needed
        if query.startswith('http://') or query.startswith('https://'):
            parsed = urlparse(query)
            query = parsed.netloc or parsed.path
        query = query.replace('www.', '')
        
        # Shodan API call
        api_key = os.getenv("SHODAN_API_KEY")
        response = requests.get(
            f"https://api.shodan.io/shodan/host/search",
            params={"key": api_key, "query": query, "minify": True},
            timeout=30
        )
        response.raise_for_status()
        
        results = response.json()
        matches = results.get("matches", [])
        
        update_scan_status(
            scan_id=scan_id,
            status="completed",
            raw_output=json.dumps(results),
            summary=f"Shodan: {len(matches)} results found",
            vulnerabilities_found=len(matches),
            risk_level="medium" if len(matches) > 0 else "low"
        )
        
        return {"success": True, "scan_id": scan_id, "results": len(matches)}
        
    except Exception as e:
        update_scan_status(scan_id, "failed", error_message=str(e))
        raise self.retry(exc=e, countdown=60, max_retries=1)


@celery_app.task(name="workers.scan_tasks.cleanup_old_scans")
def cleanup_old_scans():
    """
    Periodic task to clean up old scan data
    Runs hourly via Celery Beat
    """
    try:
        from database.connection import get_db_connection
        
        # Delete scans older than 90 days
        cutoff_date = datetime.now() - timedelta(days=90)
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM scans WHERE created_at < %s AND status = 'completed'",
                (cutoff_date,)
            )
            deleted_count = cursor.rowcount
            conn.commit()
            cursor.close()
        
        return {"deleted_scans": deleted_count}
        
    except Exception as e:
        print(f"Cleanup failed: {e}")
        return {"error": str(e)}


@celery_app.task(bind=True, name="workers.scan_tasks.batch_scan")
def batch_scan(self, targets: list, scan_type: str = "quick"):
    """
    Batch scanning multiple targets
    
    Args:
        targets: List of target IPs/domains
        scan_type: Type of scan to perform
    """
    results = []
    
    for target in targets:
        try:
            # Create scan record
            scan = create_scan(
                user_id=1,  # System user for batch scans
                target=target,
                scan_type="nmap",
                tool="nmap"
            )
            
            # Queue individual scan
            result = run_nmap_scan.delay(scan["id"], target, scan_type)
            results.append({
                "target": target,
                "scan_id": scan["id"],
                "task_id": result.id
            })
            
        except Exception as e:
            results.append({
                "target": target,
                "error": str(e)
            })
    
    return {"batch_results": results, "total": len(targets)}
