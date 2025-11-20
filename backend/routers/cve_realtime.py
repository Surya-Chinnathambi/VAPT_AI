"""
Real-Time CVE Intelligence Router
Provides endpoints for fetching and analyzing current CVE data
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from typing import Optional, List
from datetime import datetime
import logging

from services.nvd_service import NVDService
from services.threat_intelligence_service import ThreatIntelligenceService, get_threat_intelligence_service
from routers.auth import verify_token

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/today")
async def get_todays_cves(
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
    user: dict = Depends(verify_token),
    threat_intel: ThreatIntelligenceService = Depends(get_threat_intelligence_service)
):
    """
    Get today's CVEs with real-time data from NVD and CISA
    
    **Current Date Check:** Uses actual system date, not AI training data
    **Sources:** NVD API v2.0, CISA KEV Catalog
    **Accuracy:** Real-time data updated every API call
    """
    try:
        current_date = datetime.now()
        
        logger.info(f"Fetching today's CVEs for user {user.get('username')} - Date: {current_date.date()}")
        
        # Get comprehensive threat intelligence
        threat_report = await threat_intel.get_todays_critical_threats()
        
        # Filter by severity if requested
        cves = threat_report['all_threats']
        if severity:
            cves = [c for c in cves if c.get('severity') == severity.upper()]
        
        # Generate daily brief
        daily_brief = threat_intel.generate_daily_brief(cves)
        
        return {
            'success': True,
            'current_date': current_date.strftime("%Y-%m-%d"),
            'current_time': current_date.strftime("%H:%M:%S UTC"),
            'query_timestamp': current_date.isoformat(),
            'summary': {
                'total_cves': len(cves),
                'by_severity': threat_report.get('sources', {}),
                'actively_exploited': threat_report['actively_exploited'],
                'with_exploits': threat_report['with_exploits']
            },
            'daily_brief': daily_brief,
            'cves': cves[:50],  # Return top 50 to avoid overwhelming response
            'sources': [
                'NVD API v2.0 (nvd.nist.gov)',
                'CISA KEV Catalog (cisa.gov/kev)'
            ],
            'data_freshness': 'Real-time (fetched on request)',
            'next_update': 'On next API call'
        }
        
    except Exception as e:
        logger.error(f"Error fetching today's CVEs: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch CVE data: {str(e)}")


@router.get("/recent")
async def get_recent_cves(
    days: int = Query(7, ge=1, le=90, description="Number of days to look back (1-90)"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    user: dict = Depends(verify_token)
):
    """
    Get CVEs from the last N days
    
    **Parameters:**
    - days: 1-90 days lookback period
    - severity: CRITICAL, HIGH, MEDIUM, LOW
    """
    try:
        nvd = NVDService()
        
        logger.info(f"Fetching CVEs from last {days} days")
        
        cves = nvd.get_recent_cves(days=days, severity=severity)
        
        # Get statistics
        stats = nvd.get_statistics(days=days)
        
        return {
            'success': True,
            'period': f'Last {days} days',
            'start_date': (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d"),
            'end_date': datetime.now().strftime("%Y-%m-%d"),
            'statistics': stats,
            'total_cves': len(cves),
            'cves': cves,
            'source': 'NVD API v2.0'
        }
        
    except Exception as e:
        logger.error(f"Error fetching recent CVEs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/search")
async def search_cves(
    keyword: str = Query(..., min_length=3, description="Search keyword (product, vendor, etc.)"),
    days: int = Query(30, ge=1, le=365, description="Search within last N days"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    user: dict = Depends(verify_token)
):
    """
    Search CVEs by keyword
    
    **Examples:**
    - keyword=wordpress
    - keyword=microsoft exchange
    - keyword=apache
    """
    try:
        nvd = NVDService()
        
        logger.info(f"Searching CVEs with keyword: {keyword}")
        
        cves = nvd.search_cves(keyword=keyword, days=days, severity=severity)
        
        return {
            'success': True,
            'keyword': keyword,
            'period_days': days,
            'total_results': len(cves),
            'cves': cves,
            'source': 'NVD API v2.0'
        }
        
    except Exception as e:
        logger.error(f"CVE search error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/cve/{cve_id}")
async def get_cve_details(
    cve_id: str,
    user: dict = Depends(verify_token)
):
    """
    Get detailed information for a specific CVE
    
    **Example:** /api/cves/cve/CVE-2024-1234
    """
    try:
        # Validate CVE ID format
        if not cve_id.upper().startswith('CVE-'):
            raise HTTPException(status_code=400, detail="Invalid CVE ID format. Expected: CVE-YYYY-NNNNN")
        
        nvd = NVDService()
        
        logger.info(f"Fetching details for CVE: {cve_id}")
        
        cve = nvd.get_cve_by_id(cve_id)
        
        if not cve:
            raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found in NVD database")
        
        return {
            'success': True,
            'cve': cve,
            'source': 'NVD API v2.0',
            'fetched_at': datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching CVE {cve_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/product/{product_name}")
async def get_product_vulnerabilities(
    product_name: str,
    days: int = Query(30, ge=1, le=365),
    user: dict = Depends(verify_token),
    threat_intel: ThreatIntelligenceService = Depends(get_threat_intelligence_service)
):
    """
    Get all vulnerabilities affecting a specific product
    
    **Example:** /api/cves/product/wordpress
    """
    try:
        logger.info(f"Searching vulnerabilities for product: {product_name}")
        
        cves = threat_intel.search_product_vulnerabilities(product_name, days=days)
        
        return {
            'success': True,
            'product': product_name,
            'period_days': days,
            'total_vulnerabilities': len(cves),
            'by_severity': {
                'critical': len([c for c in cves if c.get('severity') == 'CRITICAL']),
                'high': len([c for c in cves if c.get('severity') == 'HIGH']),
                'medium': len([c for c in cves if c.get('severity') == 'MEDIUM']),
                'low': len([c for c in cves if c.get('severity') == 'LOW'])
            },
            'with_exploits': len([c for c in cves if c.get('has_exploit')]),
            'cves': cves,
            'source': 'NVD API v2.0'
        }
        
    except Exception as e:
        logger.error(f"Error searching product vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics")
async def get_cve_statistics(
    days: int = Query(7, ge=1, le=90),
    user: dict = Depends(verify_token)
):
    """
    Get CVE statistics for the specified period
    """
    try:
        nvd = NVDService()
        stats = nvd.get_statistics(days=days)
        
        return {
            'success': True,
            'statistics': stats
        }
        
    except Exception as e:
        logger.error(f"Error fetching statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/daily-brief")
async def get_daily_threat_brief(
    user: dict = Depends(verify_token),
    threat_intel: ThreatIntelligenceService = Depends(get_threat_intelligence_service)
):
    """
    Get a comprehensive daily threat intelligence brief
    
    **Perfect for:** Morning security briefings, executive summaries
    **Includes:** Active exploits, critical CVEs, recommendations
    """
    try:
        current_date = datetime.now()
        
        logger.info(f"Generating daily threat brief for {current_date.date()}")
        
        # Get today's threats
        threat_report = await threat_intel.get_todays_critical_threats()
        
        # Generate comprehensive brief
        brief = threat_intel.generate_daily_brief(threat_report['all_threats'])
        
        return {
            'success': True,
            'report_type': 'Daily Threat Intelligence Brief',
            'generated_at': current_date.isoformat(),
            'brief': brief,
            'raw_data': threat_report,
            'disclaimer': 'This data is fetched in real-time from authoritative sources (NVD, CISA). '
                         'Always verify critical findings before taking action.'
        }
        
    except Exception as e:
        logger.error(f"Error generating daily brief: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Import timedelta for recent endpoint
from datetime import timedelta
