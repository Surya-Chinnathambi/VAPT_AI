from fastapi import APIRouter, HTTPException, Depends, Request
import requests
from typing import List, Optional
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta
import os

from routers.auth import verify_token
from database.connection import get_db_connection
from utils.ai_helper import generate_ai_response
from core.rate_limiting import limiter, cve_search_limit

router = APIRouter()

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXPLOITDB_API = "https://www.exploit-db.com/search"

@router.get("/search")
@limiter.limit("30/minute")  # Rate limit: 30 CVE searches per minute
async def search_cves(
    request: Request,
    keyword: str,
    limit: int = 20,
    realtime: bool = True,
    user_data: dict = Depends(verify_token)
):
    """Search CVEs with real-time updates from NVD and local database"""
    try:
        # First check local database
        local_cves = search_local_cves(keyword, limit)
        
        # If realtime enabled, fetch from NVD
        if realtime:
            params = {
                'keywordSearch': keyword,
                'resultsPerPage': limit
            }
            
            response = requests.get(NVD_BASE_URL, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = []
        
        for item in data.get('vulnerabilities', []):
            cve = item.get('cve', {})
            cve_id = cve.get('id', 'Unknown')
            
            descriptions = cve.get('descriptions', [])
            description = descriptions[0].get('value', '') if descriptions else ''
            
            metrics = cve.get('metrics', {})
            cvss_score = 0.0
            
            for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if version in metrics and metrics[version]:
                    metric = metrics[version][0]
                    if 'cvssData' in metric:
                        cvss_score = metric['cvssData'].get('baseScore', 0.0)
                        break
            
            # Check for linked exploits
            linked_exploits = get_exploits_for_cve(cve_id)
            
            vulnerabilities.append({
                'cve_id': cve_id,
                'description': description,
                'cvss_score': cvss_score,
                'severity': get_severity_from_score(cvss_score),
                'published_date': cve.get('published', ''),
                'modified_date': cve.get('lastModified', ''),
                'exploits_available': len(linked_exploits) > 0,
                'exploit_count': len(linked_exploits),
                'exploits': linked_exploits[:3]  # Show first 3 exploits
            })
            
            # Cache in local database
            cache_cve_to_db(cve_id, description, cvss_score, cve.get('published', ''))
        
        # Merge with local results
        all_cves = merge_cve_results(local_cves, vulnerabilities)
        
        return {"cves": all_cves, "source": "realtime" if realtime else "local"}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CVE search failed: {str(e)}")

@router.get("/details/{cve_id}")
async def get_cve_details(
    cve_id: str,
    user_data: dict = Depends(verify_token)
):
    try:
        params = {'cveId': cve_id}
        response = requests.get(NVD_BASE_URL, params=params, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        
        if not data.get('vulnerabilities'):
            raise HTTPException(status_code=404, detail="CVE not found")
        
        item = data['vulnerabilities'][0]
        cve = item.get('cve', {})
        
        descriptions = cve.get('descriptions', [])
        description = descriptions[0].get('value', '') if descriptions else ''
        
        metrics = cve.get('metrics', {})
        cvss_score = 0.0
        cvss_vector = ""
        
        for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            if version in metrics and metrics[version]:
                metric = metrics[version][0]
                if 'cvssData' in metric:
                    cvss_score = metric['cvssData'].get('baseScore', 0.0)
                    cvss_vector = metric['cvssData'].get('vectorString', '')
                    break
        
        references = []
        for ref in cve.get('references', []):
            references.append({
                'url': ref.get('url', ''),
                'source': ref.get('source', ''),
                'tags': ref.get('tags', [])
            })
        
        # Get linked exploits
        linked_exploits = get_exploits_for_cve(cve_id)
        
        return {
            'cve_id': cve_id,
            'description': description,
            'cvss_score': cvss_score,
            'cvss_vector': cvss_vector,
            'severity': get_severity_from_score(cvss_score),
            'published_date': cve.get('published', ''),
            'modified_date': cve.get('lastModified', ''),
            'references': references,
            'exploits': linked_exploits
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching CVE details: {str(e)}")

@router.get("/ai-search")
@limiter.limit("10/minute")  # Lower limit for AI searches (expensive)
async def ai_cve_search(
    request: Request,
    query: str,
    limit: int = 20,
    user_data: dict = Depends(verify_token)
):
    """AI-powered CVE search - example: 'CVE for Apache server'"""
    try:
        # Use AI to extract keywords
        ai_prompt = f"""Extract the main software/product name from: '{query}'
Return only the product name. Example: 'CVE for Apache server' -> 'Apache HTTP Server'
Query: {query}
Keywords:"""
        
        keywords = await generate_ai_response(ai_prompt, user_data['user_id'])
        keywords = keywords.strip()
        
        # Search CVEs
        params = {'keywordSearch': keywords, 'resultsPerPage': limit}
        response = requests.get(NVD_BASE_URL, params=params, timeout=30)
        response.raise_for_status()
        
        vulnerabilities = []
        for item in response.json().get('vulnerabilities', []):
            cve = item.get('cve', {})
            cve_id = cve.get('id')
            descriptions = cve.get('descriptions', [])
            description = descriptions[0].get('value', '') if descriptions else ''
            
            metrics = cve.get('metrics', {})
            cvss_score = 0.0
            for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if version in metrics and metrics[version]:
                    cvss_score = metrics[version][0]['cvssData'].get('baseScore', 0.0)
                    break
            
            linked_exploits = get_exploits_for_cve(cve_id)
            
            vulnerabilities.append({
                'cve_id': cve_id,
                'description': description,
                'cvss_score': cvss_score,
                'severity': get_severity_from_score(cvss_score),
                'published_date': cve.get('published', ''),
                'exploits_available': len(linked_exploits) > 0,
                'exploit_count': len(linked_exploits),
                'exploits': linked_exploits[:3]
            })
        
        return {"cves": vulnerabilities, "search_keywords": keywords, "total": len(vulnerabilities)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/recent")
async def get_recent_cves(days: int = 7, limit: int = 50, user_data: dict = Depends(verify_token)):
    """Get recent CVEs with real-time updates"""
    try:
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        params = {
            'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.999'),
            'resultsPerPage': limit
        }
        
        response = requests.get(NVD_BASE_URL, params=params, timeout=30)
        response.raise_for_status()
        
        vulnerabilities = []
        for item in response.json().get('vulnerabilities', []):
            cve = item.get('cve', {})
            cve_id = cve.get('id')
            descriptions = cve.get('descriptions', [])
            description = descriptions[0].get('value', '') if descriptions else ''
            
            metrics = cve.get('metrics', {})
            cvss_score = 0.0
            for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if version in metrics and metrics[version]:
                    cvss_score = metrics[version][0]['cvssData'].get('baseScore', 0.0)
                    break
            
            linked_exploits = get_exploits_for_cve(cve_id)
            
            vulnerabilities.append({
                'cve_id': cve_id,
                'description': description[:200] + '...',
                'cvss_score': cvss_score,
                'severity': get_severity_from_score(cvss_score),
                'published_date': cve.get('published', ''),
                'exploits_available': len(linked_exploits) > 0
            })
        
        return {"cves": vulnerabilities, "date_range": f"{start_date.date()} to {end_date.date()}", "total": len(vulnerabilities)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def get_severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score >= 0.1:
        return "LOW"
    else:
        return "NONE"

def search_local_cves(keyword: str, limit: int):
    """Search local CVE database"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT * FROM cves 
                WHERE cve_id ILIKE %s OR description ILIKE %s 
                ORDER BY published_date DESC LIMIT %s
            """, (f"%{keyword}%", f"%{keyword}%", limit))
            results = cursor.fetchall()
            cursor.close()
            return [dict(r) for r in results]
    except:
        return []

def cache_cve_to_db(cve_id: str, description: str, cvss_score: float, published: str):
    """Cache CVE to local database"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO cves (cve_id, description, cvss_score, severity, published_date)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (cve_id) DO UPDATE SET
                    description = EXCLUDED.description,
                    cvss_score = EXCLUDED.cvss_score,
                    last_modified = CURRENT_TIMESTAMP
            """, (cve_id, description, cvss_score, get_severity_from_score(cvss_score), published))
            conn.commit()
            cursor.close()
    except:
        pass

def merge_cve_results(local: list, remote: list) -> list:
    """Merge local and remote CVE results"""
    seen = set()
    merged = []
    for cve in remote + local:
        if cve['cve_id'] not in seen:
            seen.add(cve['cve_id'])
            merged.append(cve)
    return merged

def get_exploits_for_cve(cve_id: str) -> list:
    """Get exploits linked to a CVE"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT edb_id, title, exploit_type, platform, author
                FROM exploits 
                WHERE cve_id = %s
                LIMIT 10
            """, (cve_id,))
            results = cursor.fetchall()
            cursor.close()
            return [dict(r) for r in results]
    except:
        return []

