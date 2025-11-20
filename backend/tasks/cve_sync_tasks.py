"""
CVE Sync Tasks - Daily sync with NVD database
Fetches, parses, and embeds CVEs into ChromaDB
"""
import requests
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict
from celery_config import celery_app
from config import NVD_API_KEY

# Try PostgreSQL first, fallback to SQLite
try:
    from database.connection import get_db_cursor
    USE_POSTGRES = True
except:
    USE_POSTGRES = False

try:
    from services.vector_db_service import get_vector_db
    USE_CHROMA = True
except:
    USE_CHROMA = False

logger = logging.getLogger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

@celery_app.task(name='tasks.cve_sync_tasks.sync_nvd_cves')
def sync_nvd_cves(days_back: int = 7):
    """
    Sync CVEs from NVD for the last N days
    
    Args:
        days_back: Number of days to look back
    """
    logger.info(f"Starting NVD CVE sync for last {days_back} days")
    
    try:
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days_back)
        
        # Format dates for NVD API
        start_date_str = start_date.strftime("%Y-%m-%dT00:00:00.000")
        end_date_str = end_date.strftime("%Y-%m-%dT23:59:59.999")
        
        # Build request
        headers = {}
        if NVD_API_KEY:
            headers['apiKey'] = NVD_API_KEY
        
        params = {
            'pubStartDate': start_date_str,
            'pubEndDate': end_date_str,
            'resultsPerPage': 100
        }
        
        cves_processed = 0
        start_index = 0
        
        while True:
            params['startIndex'] = start_index
            
            logger.info(f"Fetching CVEs from index {start_index}")
            response = requests.get(
                NVD_BASE_URL,
                params=params,
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            
            if not vulnerabilities:
                break
            
            # Process each CVE
            for item in vulnerabilities:
                try:
                    cve_data = parse_cve(item)
                    store_cve(cve_data)
                    cves_processed += 1
                except Exception as e:
                    logger.error(f"Error processing CVE: {e}")
            
            # Check if more results
            total_results = data.get('totalResults', 0)
            if start_index + len(vulnerabilities) >= total_results:
                break
            
            start_index += len(vulnerabilities)
        
        logger.info(f"CVE sync completed. Processed {cves_processed} CVEs")
        
        return {
            "success": True,
            "cves_processed": cves_processed
        }
        
    except Exception as e:
        logger.error(f"CVE sync failed: {e}")
        return {
            "success": False,
            "error": str(e)
        }

def parse_cve(item: Dict) -> Dict:
    """Parse CVE data from NVD API response"""
    cve = item.get('cve', {})
    cve_id = cve.get('id', 'Unknown')
    
    # Get description
    descriptions = cve.get('descriptions', [])
    description = descriptions[0].get('value', '') if descriptions else ''
    
    # Get CVSS scores
    metrics = cve.get('metrics', {})
    cvss_v3_score = None
    cvss_v2_score = None
    severity = 'UNKNOWN'
    
    # Try CVSSv3
    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
        metric = metrics['cvssMetricV31'][0]
        cvss_data = metric.get('cvssData', {})
        cvss_v3_score = cvss_data.get('baseScore', 0.0)
        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
    elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
        metric = metrics['cvssMetricV30'][0]
        cvss_data = metric.get('cvssData', {})
        cvss_v3_score = cvss_data.get('baseScore', 0.0)
        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
    
    # Try CVSSv2
    if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
        metric = metrics['cvssMetricV2'][0]
        cvss_data = metric.get('cvssData', {})
        cvss_v2_score = cvss_data.get('baseScore', 0.0)
    
    # Get references
    references = [
        {
            'url': ref.get('url'),
            'source': ref.get('source')
        }
        for ref in cve.get('references', [])
    ]
    
    # Get weaknesses (CWE)
    weaknesses = cve.get('weaknesses', [])
    cwe_ids = []
    for weakness in weaknesses:
        for desc in weakness.get('description', []):
            cwe_id = desc.get('value', '')
            if cwe_id.startswith('CWE-'):
                cwe_ids.append(cwe_id)
    
    # Get published/modified dates
    published_date = cve.get('published', '')
    modified_date = cve.get('lastModified', '')
    
    return {
        'cve_id': cve_id,
        'description': description,
        'cvss_v3_score': cvss_v3_score,
        'cvss_v2_score': cvss_v2_score,
        'severity': severity,
        'published_date': published_date,
        'modified_date': modified_date,
        'references': references,
        'cwe_ids': cwe_ids
    }

def store_cve(cve_data: Dict):
    """Store CVE in database and vector database"""
    try:
        # Store in relational database
        if USE_POSTGRES:
            with get_db_cursor() as cursor:
                cursor.execute("""
                    INSERT INTO cves (
                        cve_id, description, cvss_v3_score, cvss_v2_score,
                        severity, published_date, modified_date, references, cwe_ids
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (cve_id) DO UPDATE SET
                        description = EXCLUDED.description,
                        cvss_v3_score = EXCLUDED.cvss_v3_score,
                        cvss_v2_score = EXCLUDED.cvss_v2_score,
                        severity = EXCLUDED.severity,
                        modified_date = EXCLUDED.modified_date,
                        references = EXCLUDED.references,
                        cwe_ids = EXCLUDED.cwe_ids,
                        updated_at = CURRENT_TIMESTAMP
                """, (
                    cve_data['cve_id'],
                    cve_data['description'],
                    cve_data['cvss_v3_score'],
                    cve_data['cvss_v2_score'],
                    cve_data['severity'],
                    cve_data['published_date'],
                    cve_data['modified_date'],
                    json.dumps(cve_data['references']),
                    json.dumps(cve_data['cwe_ids'])
                ))
        
        # Store in vector database for semantic search
        if USE_CHROMA:
            vector_db = get_vector_db()
            vector_db.add_cve(
                cve_id=cve_data['cve_id'],
                description=cve_data['description'],
                metadata={
                    'cvss_score': cve_data.get('cvss_v3_score', 0),
                    'severity': cve_data['severity'],
                    'published_date': cve_data['published_date'],
                    'cwe_ids': json.dumps(cve_data['cwe_ids'])
                }
            )
        
        logger.info(f"Stored CVE: {cve_data['cve_id']}")
        
    except Exception as e:
        logger.error(f"Error storing CVE {cve_data['cve_id']}: {e}")

@celery_app.task(name='tasks.cve_sync_tasks.sync_recent_cves')
def sync_recent_cves():
    """Sync CVEs from the last 24 hours (daily task)"""
    return sync_nvd_cves(days_back=1)

@celery_app.task(name='tasks.cve_sync_tasks.full_cve_sync')
def full_cve_sync():
    """Full CVE sync for initial setup (last 30 days)"""
    return sync_nvd_cves(days_back=30)

@celery_app.task(name='tasks.cve_sync_tasks.search_cves')
def search_cves(query: str, limit: int = 20):
    """
    Search CVEs by keyword
    
    Args:
        query: Search keyword
        limit: Max results
    """
    try:
        if USE_CHROMA:
            # Use semantic search
            vector_db = get_vector_db()
            results = vector_db.search_cves(query, n_results=limit)
            
            return {
                "success": True,
                "results": [
                    {
                        "cve_id": results['ids'][i],
                        "description": results['documents'][i],
                        "severity": results['metadatas'][i].get('severity'),
                        "cvss_score": results['metadatas'][i].get('cvss_score'),
                        "relevance": 1 - results['distances'][i]
                    }
                    for i in range(len(results['ids']))
                ]
            }
        else:
            # Fallback to API search
            params = {
                'keywordSearch': query,
                'resultsPerPage': limit
            }
            
            headers = {}
            if NVD_API_KEY:
                headers['apiKey'] = NVD_API_KEY
            
            response = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = []
            
            for item in data.get('vulnerabilities', []):
                cve_data = parse_cve(item)
                vulnerabilities.append(cve_data)
            
            return {
                "success": True,
                "results": vulnerabilities
            }
            
    except Exception as e:
        logger.error(f"CVE search failed: {e}")
        return {
            "success": False,
            "error": str(e)
        }
