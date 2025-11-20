"""
Threat Intelligence Service
Aggregates CVE data from multiple sources and provides AI-enhanced analysis
"""

import os
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import logging
import json

from services.nvd_service import NVDService

logger = logging.getLogger(__name__)


class ThreatIntelligenceService:
    """Aggregates threat intelligence from multiple sources"""
    
    def __init__(self, nvd_api_key: Optional[str] = None):
        self.nvd = NVDService(api_key=nvd_api_key)
        self.cisa_kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    async def get_todays_critical_threats(self) -> Dict:
        """
        Get today's critical security threats from all sources
        
        Returns:
            Comprehensive threat intelligence report
        """
        current_date = datetime.now()
        
        logger.info("Fetching today's critical threats...")
        
        # Source 1: NVD Critical CVEs (last 24 hours)
        nvd_critical = self.nvd.get_recent_cves(days=1, severity="CRITICAL")
        nvd_high = self.nvd.get_recent_cves(days=1, severity="HIGH")
        
        # Source 2: CISA Known Exploited Vulnerabilities
        cisa_kev = await self.get_cisa_kev_today()
        
        # Merge and deduplicate
        all_cves = self._merge_and_deduplicate(nvd_critical, nvd_high, cisa_kev)
        
        # Prioritize by risk
        prioritized = self._prioritize_by_risk(all_cves)
        
        return {
            'report_date': current_date.strftime("%Y-%m-%d"),
            'report_time': current_date.strftime("%H:%M:%S UTC"),
            'total_critical': len([c for c in all_cves if c.get('severity') == 'CRITICAL']),
            'total_high': len([c for c in all_cves if c.get('severity') == 'HIGH']),
            'actively_exploited': len([c for c in all_cves if c.get('exploitation_status') == 'active_exploitation']),
            'with_exploits': len([c for c in all_cves if c.get('has_exploit')]),
            'top_threats': prioritized[:10],  # Top 10 most critical
            'all_threats': all_cves,
            'sources': {
                'nvd_critical': len(nvd_critical),
                'nvd_high': len(nvd_high),
                'cisa_kev': len(cisa_kev)
            }
        }
    
    async def get_cisa_kev_today(self) -> List[Dict]:
        """
        Get CISA Known Exploited Vulnerabilities added today
        
        Returns:
            List of CVEs from CISA KEV catalog
        """
        try:
            response = requests.get(self.cisa_kev_url, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            # Filter for vulnerabilities added in last 24 hours
            today = datetime.now().date()
            yesterday = today - timedelta(days=1)
            
            recent_kev = []
            for vuln in data.get('vulnerabilities', []):
                try:
                    date_added = datetime.strptime(vuln['dateAdded'], '%Y-%m-%d').date()
                    
                    if date_added >= yesterday:
                        recent_kev.append({
                            'id': vuln.get('cveID'),
                            'description': vuln.get('shortDescription', 'N/A'),
                            'vendor': vuln.get('vendorProject', 'N/A'),
                            'product': vuln.get('product', 'N/A'),
                            'vulnerability_name': vuln.get('vulnerabilityName', 'N/A'),
                            'date_added': vuln.get('dateAdded'),
                            'due_date': vuln.get('dueDate'),
                            'required_action': vuln.get('requiredAction', 'N/A'),
                            'severity': 'CRITICAL',  # CISA KEV are actively exploited = critical
                            'exploitation_status': 'active_exploitation',
                            'has_exploit': True,
                            'source': 'CISA KEV Catalog',
                            'affected_products': [f"{vuln.get('vendorProject')} {vuln.get('product')}"]
                        })
                except Exception as e:
                    logger.error(f"Error parsing CISA KEV entry: {e}")
                    continue
            
            logger.info(f"Fetched {len(recent_kev)} CVEs from CISA KEV")
            return recent_kev
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch CISA KEV: {e}")
            return []
    
    def _merge_and_deduplicate(self, *sources: List[Dict]) -> List[Dict]:
        """
        Merge CVEs from multiple sources and remove duplicates
        
        Args:
            *sources: Variable number of CVE lists
        
        Returns:
            Deduplicated list of CVEs
        """
        cve_dict = {}
        
        for source in sources:
            for cve in source:
                cve_id = cve.get('id')
                
                if not cve_id:
                    continue
                
                # If CVE already exists, merge information
                if cve_id in cve_dict:
                    existing = cve_dict[cve_id]
                    
                    # Use highest severity
                    severity_priority = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}
                    if severity_priority.get(cve.get('severity', 'UNKNOWN'), 0) > \
                       severity_priority.get(existing.get('severity', 'UNKNOWN'), 0):
                        existing['severity'] = cve.get('severity')
                    
                    # Merge exploitation status (prefer active > exploit > poc > none)
                    if cve.get('exploitation_status') == 'active_exploitation':
                        existing['exploitation_status'] = 'active_exploitation'
                        existing['has_exploit'] = True
                    elif cve.get('has_exploit') and not existing.get('has_exploit'):
                        existing['has_exploit'] = True
                    
                    # Merge references
                    if 'references' in cve:
                        existing.setdefault('references', []).extend(cve['references'])
                    
                    # Add source attribution
                    existing.setdefault('data_sources', []).append(cve.get('source', 'Unknown'))
                    
                else:
                    cve_dict[cve_id] = cve.copy()
                    cve_dict[cve_id]['data_sources'] = [cve.get('source', 'NVD')]
        
        return list(cve_dict.values())
    
    def _prioritize_by_risk(self, cves: List[Dict]) -> List[Dict]:
        """
        Prioritize CVEs by actual risk (not just CVSS score)
        
        Priority factors:
        1. Active exploitation (CISA KEV)
        2. Public exploit available
        3. CVSS score
        4. Exploitability score
        5. Recency (published date)
        
        Returns:
            Sorted list of CVEs (highest risk first)
        """
        def risk_score(cve: Dict) -> float:
            score = 0.0
            
            # Active exploitation: +50 points
            if cve.get('exploitation_status') == 'active_exploitation':
                score += 50
            
            # Exploit exists: +30 points
            elif cve.get('has_exploit'):
                score += 30
            
            # PoC available: +20 points
            elif cve.get('exploitation_status') == 'poc_available':
                score += 20
            
            # CVSS base score: +0-10 points
            score += cve.get('cvss_score', 0)
            
            # Exploitability score: +0-10 points
            score += cve.get('exploitability_score', 0)
            
            # Recency bonus: +0-5 points (newer = more points)
            try:
                pub_date = datetime.fromisoformat(cve.get('published_date', '').replace('Z', '+00:00'))
                hours_old = (datetime.now(pub_date.tzinfo) - pub_date).total_seconds() / 3600
                recency_bonus = max(0, 5 - (hours_old / 24))  # Linear decay over 24 hours
                score += recency_bonus
            except:
                pass
            
            # Severity multiplier
            severity_multipliers = {
                'CRITICAL': 1.5,
                'HIGH': 1.2,
                'MEDIUM': 1.0,
                'LOW': 0.8,
                'UNKNOWN': 0.5
            }
            score *= severity_multipliers.get(cve.get('severity', 'UNKNOWN'), 1.0)
            
            return score
        
        # Sort by risk score (highest first)
        prioritized = sorted(cves, key=risk_score, reverse=True)
        
        # Add priority rank
        for i, cve in enumerate(prioritized, 1):
            cve['priority_rank'] = i
            cve['risk_score'] = round(risk_score(cve), 2)
        
        return prioritized
    
    def search_product_vulnerabilities(self, product_name: str, days: int = 30) -> List[Dict]:
        """
        Search for vulnerabilities affecting a specific product
        
        Args:
            product_name: Product name to search for
            days: Number of days to search back
        
        Returns:
            List of matching CVEs
        """
        logger.info(f"Searching vulnerabilities for: {product_name}")
        
        # Search NVD
        cves = self.nvd.search_cves(keyword=product_name, days=days)
        
        # Prioritize results
        prioritized = self._prioritize_by_risk(cves)
        
        return prioritized
    
    def generate_daily_brief(self, cves: List[Dict]) -> Dict:
        """
        Generate a human-readable daily threat intelligence brief
        
        Args:
            cves: List of CVEs to analyze
        
        Returns:
            Structured brief with key findings
        """
        current_date = datetime.now()
        
        # Categorize CVEs
        actively_exploited = [c for c in cves if c.get('exploitation_status') == 'active_exploitation']
        with_exploits = [c for c in cves if c.get('has_exploit') and c not in actively_exploited]
        critical = [c for c in cves if c.get('severity') == 'CRITICAL']
        high = [c for c in cves if c.get('severity') == 'HIGH']
        
        # Extract affected products
        all_products = set()
        for cve in cves:
            all_products.update(cve.get('affected_products', []))
        
        # Top vendors affected
        vendor_count = {}
        for product in all_products:
            vendor = product.split()[0] if product else 'Unknown'
            vendor_count[vendor] = vendor_count.get(vendor, 0) + 1
        
        top_vendors = sorted(vendor_count.items(), key=lambda x: x[1], reverse=True)[:5]
        
        brief = {
            'date': current_date.strftime("%B %d, %Y"),
            'time': current_date.strftime("%H:%M UTC"),
            'summary': {
                'total_cves': len(cves),
                'actively_exploited': len(actively_exploited),
                'with_public_exploits': len(with_exploits),
                'critical_severity': len(critical),
                'high_severity': len(high),
                'requires_immediate_action': len(actively_exploited)
            },
            'top_threats': cves[:5] if cves else [],
            'actively_exploited_cves': actively_exploited,
            'top_affected_vendors': [
                {'vendor': v, 'cve_count': c} for v, c in top_vendors
            ],
            'recommendations': self._generate_recommendations(cves)
        }
        
        return brief
    
    def _generate_recommendations(self, cves: List[Dict]) -> List[str]:
        """Generate actionable recommendations based on CVE analysis"""
        recommendations = []
        
        actively_exploited = [c for c in cves if c.get('exploitation_status') == 'active_exploitation']
        with_exploits = [c for c in cves if c.get('has_exploit')]
        
        if actively_exploited:
            recommendations.append(
                f"🚨 URGENT: {len(actively_exploited)} CVE(s) are being actively exploited in the wild. "
                f"Apply patches immediately for: {', '.join(c.get('id') for c in actively_exploited[:3])}"
            )
        
        if with_exploits:
            recommendations.append(
                f"⚠️ HIGH PRIORITY: {len(with_exploits)} CVE(s) have public exploit code available. "
                f"Exploitation risk is elevated."
            )
        
        if len(cves) > 10:
            recommendations.append(
                f"📊 Monitor and prioritize patching based on risk score. "
                f"Focus on top {min(10, len(cves))} highest-risk vulnerabilities first."
            )
        
        recommendations.append(
            "🔍 Scan your infrastructure to identify affected systems and prioritize remediation."
        )
        
        recommendations.append(
            "📝 Review CISA KEV catalog daily for actively exploited vulnerabilities requiring immediate action."
        )
        
        return recommendations


async def get_threat_intelligence_service() -> ThreatIntelligenceService:
    """Dependency injection helper"""
    nvd_api_key = os.getenv("NVD_API_KEY")
    return ThreatIntelligenceService(nvd_api_key=nvd_api_key)
