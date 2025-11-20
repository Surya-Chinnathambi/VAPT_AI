"""
Report Generation Background Tasks
Handles PDF/HTML report generation asynchronously
"""

from workers.celery_app import celery_app
from database.connection import get_scan_by_id, get_db_connection
import json

@celery_app.task(bind=True, name="workers.report_tasks.generate_report")
def generate_report(self, report_id: int, scan_id: int, format: str = "pdf"):
    """
    Generate security report from scan results
    
    Args:
        report_id: Database report record ID
        scan_id: Scan to generate report from
        format: pdf, html, or json
    """
    try:
        # Get scan data
        scan = get_scan_by_id(scan_id)
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        
        # Parse scan results
        results = json.loads(scan.get("raw_output", "{}"))
        
        # Generate report content
        report_data = {
            "scan_id": scan_id,
            "target": scan.get("target"),
            "scan_type": scan.get("scan_type"),
            "timestamp": str(scan.get("created_at")),
            "vulnerabilities": scan.get("vulnerabilities_found", 0),
            "risk_level": scan.get("risk_level", "unknown"),
            "summary": scan.get("summary", ""),
            "details": results
        }
        
        # Store report (simplified for now)
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """UPDATE reports 
                   SET status = 'completed', 
                       content = %s,
                       generated_at = NOW()
                   WHERE id = %s""",
                (json.dumps(report_data), report_id)
            )
            conn.commit()
            cursor.close()
        
        return {
            "success": True,
            "report_id": report_id,
            "format": format
        }
        
    except Exception as e:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE reports SET status = 'failed', error = %s WHERE id = %s",
                (str(e), report_id)
            )
            conn.commit()
            cursor.close()
        
        raise self.retry(exc=e, countdown=60, max_retries=2)


@celery_app.task(name="workers.report_tasks.send_report_email")
def send_report_email(report_id: int, recipient_email: str):
    """
    Email report to user
    
    Args:
        report_id: Report to send
        recipient_email: Recipient email address
    """
    try:
        # TODO: Implement email sending
        # For now, just log
        print(f"Sending report {report_id} to {recipient_email}")
        
        return {
            "success": True,
            "report_id": report_id,
            "recipient": recipient_email
        }
        
    except Exception as e:
        print(f"Email send failed: {e}")
        return {"error": str(e)}
