"""
Celery Tasks for Background Scanning
Handles port scans, web scans, and other security assessments
"""
import json
import logging
from datetime import datetime
from celery_config import celery_app
from services.port_scanner_service import perform_port_scan
from services.web_scanner_service import perform_web_scan
from services.ai_chat_service import get_chat_service

# Try to import PostgreSQL, fallback to SQLite
try:
    from database.connection import update_scan_status, get_scan_by_id, create_scan
    USE_POSTGRES = True
except:
    from utils.database import get_db_connection
    USE_POSTGRES = False

logger = logging.getLogger(__name__)

def update_scan_sqlite(scan_id, status, results=None, summary=None, error_message=None, 
                       vulnerabilities_found=0, risk_level=None):
    """Update scan in SQLite database"""
    from utils.database import get_db_connection
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE scan_results 
            SET status = ?, results = ?, completed_at = ?
            WHERE id = ?
        """, (status, results, datetime.now() if status in ['completed', 'failed'] else None, scan_id))
        conn.commit()

@celery_app.task(name='tasks.scan_tasks.run_port_scan', bind=True)
def run_port_scan(self, scan_id: int, target: str, ports: list = None, scan_type: str = "common"):
    """
    Execute port scan in background
    
    Args:
        scan_id: Database ID of scan record
        target: Target host/IP
        ports: List of ports to scan
        scan_type: Type of scan (common, top1000, custom)
    """
    logger.info(f"Starting port scan {scan_id} for target: {target}")
    
    try:
        # Update status to running
        if USE_POSTGRES:
            update_scan_status(scan_id, 'running')
        else:
            update_scan_sqlite(scan_id, 'running')
        
        # Perform the scan
        results = perform_port_scan(target, ports, scan_type)
        
        # Count vulnerabilities
        vulnerabilities_found = len(results.get('open_ports', []))
        
        # Determine risk level
        if vulnerabilities_found > 20:
            risk_level = 'high'
        elif vulnerabilities_found > 10:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        # Get AI analysis if available
        chat_service = get_chat_service()
        summary = f"Found {vulnerabilities_found} open ports"
        
        if chat_service.is_available():
            try:
                import asyncio
                analysis = asyncio.run(chat_service.analyze_scan_results(
                    'port_scan',
                    results
                ))
                summary = analysis.get('summary', summary)
            except Exception as e:
                logger.error(f"AI analysis failed: {e}")
        
        # Update with results
        if USE_POSTGRES:
            update_scan_status(
                scan_id, 
                'completed',
                raw_output=json.dumps(results),
                summary=summary,
                vulnerabilities_found=vulnerabilities_found,
                risk_level=risk_level
            )
        else:
            update_scan_sqlite(
                scan_id,
                'completed',
                results=json.dumps(results)
            )
        
        logger.info(f"Port scan {scan_id} completed successfully")
        return {
            "success": True,
            "scan_id": scan_id,
            "vulnerabilities_found": vulnerabilities_found,
            "risk_level": risk_level
        }
        
    except Exception as e:
        logger.error(f"Port scan {scan_id} failed: {e}")
        
        # Update with error
        if USE_POSTGRES:
            update_scan_status(scan_id, 'failed', error_message=str(e))
        else:
            update_scan_sqlite(scan_id, 'failed', error_message=str(e))
        
        return {
            "success": False,
            "error": str(e)
        }

@celery_app.task(name='tasks.scan_tasks.run_web_scan', bind=True)
def run_web_scan(self, scan_id: int, target_url: str, options: dict = None):
    """
    Execute web vulnerability scan in background
    
    Args:
        scan_id: Database ID of scan record
        target_url: Target URL
        options: Scan options
    """
    logger.info(f"Starting web scan {scan_id} for target: {target_url}")
    
    try:
        # Update status to running
        if USE_POSTGRES:
            update_scan_status(scan_id, 'running')
        else:
            update_scan_sqlite(scan_id, 'running')
        
        # Perform the scan
        results = perform_web_scan(target_url, options)
        
        # Count vulnerabilities
        risk_summary = results.get('risk_summary', {})
        vulnerabilities_found = sum(risk_summary.values())
        
        # Determine risk level
        if risk_summary.get('high', 0) > 0:
            risk_level = 'high'
        elif risk_summary.get('medium', 0) > 0:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        # Get AI analysis
        chat_service = get_chat_service()
        summary = f"Found {vulnerabilities_found} vulnerabilities"
        
        if chat_service.is_available():
            try:
                import asyncio
                analysis = asyncio.run(chat_service.analyze_scan_results(
                    'web_scan',
                    results
                ))
                summary = analysis.get('summary', summary)
            except Exception as e:
                logger.error(f"AI analysis failed: {e}")
        
        # Update with results
        if USE_POSTGRES:
            update_scan_status(
                scan_id,
                'completed',
                raw_output=json.dumps(results),
                summary=summary,
                vulnerabilities_found=vulnerabilities_found,
                risk_level=risk_level
            )
        else:
            update_scan_sqlite(
                scan_id,
                'completed',
                results=json.dumps(results)
            )
        
        logger.info(f"Web scan {scan_id} completed successfully")
        return {
            "success": True,
            "scan_id": scan_id,
            "vulnerabilities_found": vulnerabilities_found,
            "risk_level": risk_level
        }
        
    except Exception as e:
        logger.error(f"Web scan {scan_id} failed: {e}")
        
        # Update with error
        if USE_POSTGRES:
            update_scan_status(scan_id, 'failed', error_message=str(e))
        else:
            update_scan_sqlite(scan_id, 'failed', error_message=str(e))
        
        return {
            "success": False,
            "error": str(e)
        }

@celery_app.task(name='tasks.scan_tasks.run_shodan_scan')
def run_shodan_scan(scan_id: int, target: str):
    """
    Execute Shodan lookup in background
    
    Args:
        scan_id: Database ID of scan record
        target: IP address to lookup
    """
    logger.info(f"Starting Shodan scan {scan_id} for target: {target}")
    
    try:
        import shodan
        from config import SHODAN_API_KEY
        
        if not SHODAN_API_KEY:
            raise Exception("Shodan API key not configured")
        
        # Update status
        if USE_POSTGRES:
            update_scan_status(scan_id, 'running')
        else:
            update_scan_sqlite(scan_id, 'running')
        
        # Query Shodan
        api = shodan.Shodan(SHODAN_API_KEY)
        results = api.host(target)
        
        # Format results
        formatted_results = {
            "ip": results.get('ip_str'),
            "organization": results.get('org', 'Unknown'),
            "operating_system": results.get('os'),
            "ports": results.get('ports', []),
            "vulnerabilities": results.get('vulns', []),
            "services": [
                {
                    "port": item.get('port'),
                    "protocol": item.get('transport'),
                    "service": item.get('product'),
                    "version": item.get('version')
                }
                for item in results.get('data', [])
            ]
        }
        
        vulnerabilities_found = len(formatted_results.get('vulnerabilities', []))
        risk_level = 'high' if vulnerabilities_found > 0 else 'medium'
        
        # Update with results
        if USE_POSTGRES:
            update_scan_status(
                scan_id,
                'completed',
                raw_output=json.dumps(formatted_results),
                summary=f"Found {len(formatted_results['ports'])} open ports and {vulnerabilities_found} known vulnerabilities",
                vulnerabilities_found=vulnerabilities_found,
                risk_level=risk_level
            )
        else:
            update_scan_sqlite(
                scan_id,
                'completed',
                results=json.dumps(formatted_results)
            )
        
        logger.info(f"Shodan scan {scan_id} completed successfully")
        return {
            "success": True,
            "scan_id": scan_id,
            "results": formatted_results
        }
        
    except Exception as e:
        logger.error(f"Shodan scan {scan_id} failed: {e}")
        
        if USE_POSTGRES:
            update_scan_status(scan_id, 'failed', error_message=str(e))
        else:
            update_scan_sqlite(scan_id, 'failed', error_message=str(e))
        
        return {
            "success": False,
            "error": str(e)
        }

@celery_app.task(name='tasks.scan_tasks.analyze_scan_with_ai')
def analyze_scan_with_ai(scan_id: int, compliance_frameworks: list = None):
    """
    Analyze scan results with AI and update summary
    
    Args:
        scan_id: Scan ID to analyze
        compliance_frameworks: Frameworks to check against
    """
    logger.info(f"Analyzing scan {scan_id} with AI")
    
    try:
        # Get scan results
        if USE_POSTGRES:
            scan = get_scan_by_id(scan_id)
        else:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM scan_results WHERE id = ?", (scan_id,))
                scan = dict(cursor.fetchone())
        
        if not scan:
            raise Exception(f"Scan {scan_id} not found")
        
        # Parse results
        results = json.loads(scan.get('results', scan.get('raw_output', '{}')))
        
        # Get AI analysis
        chat_service = get_chat_service()
        if not chat_service.is_available():
            return {"error": "AI service not available"}
        
        import asyncio
        analysis = asyncio.run(chat_service.analyze_scan_results(
            scan.get('scan_type', scan.get('tool', 'unknown')),
            results,
            compliance_frameworks
        ))
        
        # Update scan with analysis
        if USE_POSTGRES:
            update_scan_status(
                scan_id,
                scan['status'],
                summary=analysis.get('summary'),
                risk_level=analysis.get('risk_level')
            )
        
        return {
            "success": True,
            "analysis": analysis
        }
        
    except Exception as e:
        logger.error(f"AI analysis for scan {scan_id} failed: {e}")
        return {
            "success": False,
            "error": str(e)
        }
