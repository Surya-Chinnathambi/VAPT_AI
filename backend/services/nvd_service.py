"""
NVD (National Vulnerability Database) API Service
Real-time CVE data fetching from NIST NVD API v2.0
"""

import os
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import time
import logging

logger = logging.getLogger(__name__)


class NVDService:
    """Service for fetching CVE data from NIST NVD API"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        
        # Rate limiting: With API key = 50 requests per 30 seconds, without = 5 per 30 seconds
        self.rate_limit_delay = 0.6 if self.api_key else 6.0
        self.last_request_time = 0
    
    def _rate_limit(self):
        """Enforce rate limiting between requests"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - time_since_last
            logger.info(f"Rate limiting: sleeping for {sleep_time:.2f}s")
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def get_recent_cves(
        self,
        days: int = 1,
        severity: Optional[str] = None,
        results_per_page: int = 100
    ) -> List[Dict]:
        """
        Fetch CVEs published in the last N days
        
        Args:
            days: Number of days to look back (default: 1 for today's CVEs)
            severity: Filter by CVSS v3 severity (CRITICAL, HIGH, MEDIUM, LOW)
            results_per_page: Number of results per page (max 2000)
        
        Returns:
            List of parsed CVE dictionaries
        """
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        params = {
            "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
            "resultsPerPage": results_per_page
        }
        
        if severity:
            params["cvssV3Severity"] = severity.upper()
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        logger.info(f"Fetching CVEs from {start_date.date()} to {end_date.date()}")
        
        self._rate_limit()
        
        try:
            response = requests.get(
                self.base_url,
                params=params,
                headers=headers,
                timeout=30
            )
            
            response.raise_for_status()
            data = response.json()
            
            cves = self._parse_cves(data)
            logger.info(f"Successfully fetched {len(cves)} CVEs")
            
            return cves
            
        except requests.exceptions.RequestException as e:
            logger.error(f"NVD API request failed: {e}")
            return []
    
    def get_cve_by_id(self, cve_id: str) -> Optional[Dict]:
        """
        Fetch a specific CVE by ID
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)
        
        Returns:
            Parsed CVE dictionary or None
        """
        params = {"cveId": cve_id}
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        logger.info(f"Fetching CVE: {cve_id}")
        
        self._rate_limit()
        
        try:
            response = requests.get(
                self.base_url,
                params=params,
                headers=headers,
                timeout=30
            )
            
            response.raise_for_status()
            data = response.json()
            
            cves = self._parse_cves(data)
            return cves[0] if cves else None
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch CVE {cve_id}: {e}")
            return None
    
    def search_cves(
        self,
        keyword: str,
        days: int = 30,
        severity: Optional[str] = None
    ) -> List[Dict]:
        """
        Search CVEs by keyword
        
        Args:
            keyword: Search keyword (product name, vendor, etc.)
            days: Number of days to search back
            severity: Filter by severity
        
        Returns:
            List of matching CVEs
        """
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        params = {
            "keywordSearch": keyword,
            "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
            "resultsPerPage": 100
        }
        
        if severity:
            params["cvssV3Severity"] = severity.upper()
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        logger.info(f"Searching CVEs with keyword: {keyword}")
        
        self._rate_limit()
        
        try:
            response = requests.get(
                self.base_url,
                params=params,
                headers=headers,
                timeout=30
            )
            
            response.raise_for_status()
            data = response.json()
            
            return self._parse_cves(data)
            
        except requests.exceptions.RequestException as e:
            logger.error(f"CVE search failed: {e}")
            return []
    
    def _parse_cves(self, data: Dict) -> List[Dict]:
        """
        Parse NVD API response into structured CVE data
        
        Args:
            data: Raw NVD API response
        
        Returns:
            List of parsed CVE dictionaries
        """
        cves = []
        
        for item in data.get('vulnerabilities', []):
            try:
                cve = item.get('cve', {})
                
                # Basic info
                cve_id = cve.get('id')
                source_identifier = cve.get('sourceIdentifier', 'N/A')
                
                # Description
                descriptions = cve.get('descriptions', [])
                description = next(
                    (d['value'] for d in descriptions if d.get('lang') == 'en'),
                    descriptions[0]['value'] if descriptions else 'No description available'
                )
                
                # CVSS metrics (v3.1 preferred, fallback to v3.0, then v2.0)
                metrics = cve.get('metrics', {})
                cvss_data = self._extract_cvss_metrics(metrics)
                
                # Dates
                published = cve.get('published', 'N/A')
                last_modified = cve.get('lastModified', 'N/A')
                
                # References
                references = [
                    {
                        'url': ref.get('url'),
                        'source': ref.get('source', 'N/A'),
                        'tags': ref.get('tags', [])
                    }
                    for ref in cve.get('references', [])
                ]
                
                # Weakness enumeration (CWE)
                weaknesses = []
                for weakness in cve.get('weaknesses', []):
                    for desc in weakness.get('description', []):
                        if desc.get('lang') == 'en':
                            weaknesses.append(desc.get('value'))
                
                # CPE (affected products)
                configurations = cve.get('configurations', [])
                affected_products = self._extract_affected_products(configurations)
                
                # Exploitation status (from references tags)
                exploitation_status = self._determine_exploitation_status(references)
                
                cves.append({
                    'id': cve_id,
                    'source': source_identifier,
                    'description': description,
                    'cvss_score': cvss_data['score'],
                    'cvss_version': cvss_data['version'],
                    'severity': cvss_data['severity'],
                    'vector_string': cvss_data['vector'],
                    'exploitability_score': cvss_data['exploitability'],
                    'impact_score': cvss_data['impact'],
                    'published_date': published,
                    'last_modified_date': last_modified,
                    'references': references,
                    'weaknesses': weaknesses,
                    'affected_products': affected_products,
                    'exploitation_status': exploitation_status,
                    'has_exploit': exploitation_status in ['exploit_exists', 'active_exploitation']
                })
                
            except Exception as e:
                logger.error(f"Error parsing CVE: {e}")
                continue
        
        return cves
    
    def _extract_cvss_metrics(self, metrics: Dict) -> Dict:
        """Extract CVSS metrics, preferring v3.1 > v3.0 > v2.0"""
        
        # Try CVSS v3.1
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            metric = metrics['cvssMetricV31'][0]
            cvss = metric.get('cvssData', {})
            return {
                'version': '3.1',
                'score': cvss.get('baseScore', 0),
                'severity': cvss.get('baseSeverity', 'UNKNOWN'),
                'vector': cvss.get('vectorString', 'N/A'),
                'exploitability': metric.get('exploitabilityScore', 0),
                'impact': metric.get('impactScore', 0)
            }
        
        # Try CVSS v3.0
        if 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            metric = metrics['cvssMetricV30'][0]
            cvss = metric.get('cvssData', {})
            return {
                'version': '3.0',
                'score': cvss.get('baseScore', 0),
                'severity': cvss.get('baseSeverity', 'UNKNOWN'),
                'vector': cvss.get('vectorString', 'N/A'),
                'exploitability': metric.get('exploitabilityScore', 0),
                'impact': metric.get('impactScore', 0)
            }
        
        # Fallback to CVSS v2.0
        if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            metric = metrics['cvssMetricV2'][0]
            cvss = metric.get('cvssData', {})
            score = cvss.get('baseScore', 0)
            
            # Map v2 score to severity
            if score >= 9.0:
                severity = 'CRITICAL'
            elif score >= 7.0:
                severity = 'HIGH'
            elif score >= 4.0:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'
            
            return {
                'version': '2.0',
                'score': score,
                'severity': severity,
                'vector': cvss.get('vectorString', 'N/A'),
                'exploitability': metric.get('exploitabilityScore', 0),
                'impact': metric.get('impactScore', 0)
            }
        
        # No metrics available
        return {
            'version': 'N/A',
            'score': 0,
            'severity': 'UNKNOWN',
            'vector': 'N/A',
            'exploitability': 0,
            'impact': 0
        }
    
    def _extract_affected_products(self, configurations: List[Dict]) -> List[str]:
        """Extract affected product names from CPE configurations"""
        products = set()
        
        for config in configurations:
            for node in config.get('nodes', []):
                for cpe_match in node.get('cpeMatch', []):
                    cpe_uri = cpe_match.get('criteria', '')
                    if cpe_uri:
                        # Parse CPE URI: cpe:2.3:a:vendor:product:version:...
                        parts = cpe_uri.split(':')
                        if len(parts) >= 5:
                            vendor = parts[3]
                            product = parts[4]
                            products.add(f"{vendor} {product}")
        
        return sorted(list(products))
    
    def _determine_exploitation_status(self, references: List[Dict]) -> str:
        """
        Determine exploitation status from reference tags
        
        Returns:
            'active_exploitation', 'exploit_exists', 'poc_available', or 'none'
        """
        tags_set = set()
        for ref in references:
            tags_set.update(ref.get('tags', []))
        
        if 'Exploit' in tags_set:
            return 'exploit_exists'
        
        # Check URLs for exploit indicators
        exploit_indicators = ['exploit', 'poc', 'proof-of-concept', 'metasploit', 'exploitdb']
        for ref in references:
            url = ref.get('url', '').lower()
            if any(indicator in url for indicator in exploit_indicators):
                return 'poc_available'
        
        return 'none'
    
    def get_statistics(self, days: int = 7) -> Dict:
        """
        Get CVE statistics for the last N days
        
        Args:
            days: Number of days to analyze
        
        Returns:
            Dictionary with statistics
        """
        cves = self.get_recent_cves(days=days)
        
        total = len(cves)
        by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
        with_exploits = 0
        
        for cve in cves:
            severity = cve.get('severity', 'UNKNOWN')
            by_severity[severity] = by_severity.get(severity, 0) + 1
            
            if cve.get('has_exploit'):
                with_exploits += 1
        
        return {
            'period_days': days,
            'total_cves': total,
            'by_severity': by_severity,
            'with_exploits': with_exploits,
            'exploit_percentage': round((with_exploits / total * 100) if total > 0 else 0, 2),
            'generated_at': datetime.utcnow().isoformat()
        }
