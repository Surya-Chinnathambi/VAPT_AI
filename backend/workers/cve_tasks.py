"""
CVE Database Background Tasks
Handles CVE synchronization and updates
"""

from workers.celery_app import celery_app
from database.connection import get_db_connection
import requests
from datetime import datetime, timedelta

@celery_app.task(bind=True, name="workers.cve_tasks.sync_cve_database")
def sync_cve_database(self):
    """
    Daily CVE database synchronization from NVD
    Runs automatically via Celery Beat
    """
    try:
        print("Starting CVE sync...")
        
        # Fetch recent CVEs (last 7 days)
        end_date = datetime.now()
        start_date = end_date - timedelta(days=7)
        
        params = {
            'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.999'),
            'resultsPerPage': 100
        }
        
        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params,
            timeout=30
        )
        response.raise_for_status()
        
        data = response.json()
        vulnerabilities = data.get('vulnerabilities', [])
        
        synced_count = 0
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            for item in vulnerabilities:
                try:
                    cve = item.get('cve', {})
                    cve_id = cve.get('id')
                    
                    descriptions = cve.get('descriptions', [])
                    description = descriptions[0].get('value', '') if descriptions else ''
                    
                    metrics = cve.get('metrics', {})
                    cvss_score = 0.0
                    severity = 'UNKNOWN'
                    
                    for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                        if version in metrics and metrics[version]:
                            metric = metrics[version][0]
                            if 'cvssData' in metric:
                                cvss_score = metric['cvssData'].get('baseScore', 0.0)
                                severity = metric['cvssData'].get('baseSeverity', 'UNKNOWN')
                                break
                    
                    # Upsert CVE
                    cursor.execute("""
                        INSERT INTO cves (cve_id, description, cvss_score, severity, published_date)
                        VALUES (%s, %s, %s, %s, %s)
                        ON CONFLICT (cve_id) DO UPDATE SET
                            description = EXCLUDED.description,
                            cvss_score = EXCLUDED.cvss_score,
                            severity = EXCLUDED.severity,
                            last_modified = CURRENT_TIMESTAMP
                    """, (
                        cve_id,
                        description[:1000],
                        cvss_score,
                        severity,
                        cve.get('published', '')
                    ))
                    
                    synced_count += 1
                    
                except Exception as e:
                    print(f"Error syncing {cve_id}: {e}")
                    continue
            
            conn.commit()
            cursor.close()
        
        print(f"CVE sync complete: {synced_count} CVEs synced")
        
        return {
            "success": True,
            "synced_count": synced_count,
            "date_range": f"{start_date.date()} to {end_date.date()}"
        }
        
    except Exception as e:
        print(f"CVE sync failed: {e}")
        raise self.retry(exc=e, countdown=300, max_retries=3)


@celery_app.task(name="workers.cve_tasks.check_new_critical_cves")
def check_new_critical_cves():
    """
    Check for new critical CVEs and send alerts
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get CVEs from last 24 hours with CVSS >= 9.0
            cursor.execute("""
                SELECT cve_id, description, cvss_score
                FROM cves
                WHERE cvss_score >= 9.0
                AND published_date >= NOW() - INTERVAL '24 hours'
                ORDER BY cvss_score DESC
            """)
            
            critical_cves = cursor.fetchall()
            cursor.close()
        
        if critical_cves:
            print(f"Found {len(critical_cves)} new critical CVEs!")
            # TODO: Send notification to admins
        
        return {
            "critical_cves_found": len(critical_cves),
            "cves": [row[0] for row in critical_cves]
        }
        
    except Exception as e:
        print(f"Critical CVE check failed: {e}")
        return {"error": str(e)}
