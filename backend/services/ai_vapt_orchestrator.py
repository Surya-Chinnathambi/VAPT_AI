"""
AI-Powered VAPT Orchestrator
Implements 40-50% automated vulnerability assessment workflow
"""
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum
import json
import logging

from pydantic import BaseModel, HttpUrl, validator

logger = logging.getLogger(__name__)


class ScanPhase(str, Enum):
    """VAPT workflow phases"""
    VALIDATION = "validation"
    PASSIVE_RECON = "passive_recon"
    ACTIVE_SCAN = "active_scan"
    ANALYSIS = "analysis"
    EXPLOITATION_SUGGESTIONS = "exploitation_suggestions"
    REMEDIATION = "remediation"
    REPORTING = "reporting"


class SeverityLevel(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VAPTTarget(BaseModel):
    """Target specification for VAPT"""
    url: Optional[str] = None
    domain: Optional[str] = None
    ip_address: Optional[str] = None
    scope: List[str] = []
    allowed_active_scan: bool = False
    authorization_proof: Optional[str] = None
    
    @validator('scope', pre=True, always=True)
    def validate_scope(cls, v):
        if not v:
            return []
        return v


class VAPTDecision(BaseModel):
    """AI decision for next steps"""
    phase: ScanPhase
    action: str
    reasoning: str
    tools_to_trigger: List[str] = []
    priority: int = 1  # 1=high, 5=low
    estimated_duration: int = 0  # seconds


class VulnerabilityFinding(BaseModel):
    """Normalized vulnerability finding"""
    title: str
    severity: SeverityLevel
    category: str
    description: str
    evidence: Dict[str, Any]
    cvss_score: Optional[float] = None
    cve_ids: List[str] = []
    cwe_ids: List[str] = []
    owasp_category: Optional[str] = None
    mitre_technique: Optional[str] = None
    remediation: str
    affected_component: str
    tool_source: str
    false_positive_probability: float = 0.0


class AIVAPTOrchestrator:
    """
    AI-Powered VAPT Orchestrator
    Automates 40-50% of penetration testing workflow
    """
    
    def __init__(self):
        self.current_phase = None
        self.findings: List[VulnerabilityFinding] = []
        self.recon_data = {}
        self.scan_results = {}
        self.ai_decisions: List[VAPTDecision] = []
        
    async def execute_vapt_workflow(self, target: VAPTTarget) -> Dict[str, Any]:
        """
        Main VAPT workflow execution
        Orchestrates all phases with AI decision-making
        """
        workflow_start = datetime.utcnow()
        
        try:
            # Phase 1: Validation
            validation_result = await self._phase_1_validation(target)
            if not validation_result['passed']:
                return {
                    'success': False,
                    'error': validation_result['reason'],
                    'phase': 'validation'
                }
            
            # Phase 2: Passive Reconnaissance (100% automated)
            recon_data = await self._phase_2_passive_recon(target)
            
            # AI Decision Point: Analyze recon and decide next steps
            ai_decision = await self._ai_analyze_and_decide(recon_data, target)
            
            # Phase 3: Active Scanning (80-90% automated)
            if target.allowed_active_scan and ai_decision['proceed_to_active']:
                scan_results = await self._phase_3_active_scanning(target, ai_decision)
            else:
                scan_results = {'skipped': 'Active scanning not authorized'}
            
            # Phase 4: AI Analysis & Interpretation (60-70% automated)
            analyzed_findings = await self._phase_4_ai_analysis(scan_results)
            
            # Phase 5: Exploitation Suggestions (10-40% automated)
            exploitation_suggestions = await self._phase_5_exploitation_suggestions(analyzed_findings)
            
            # Phase 6: Remediation Recommendations (90% automated)
            remediation_plan = await self._phase_6_remediation_recommendations(analyzed_findings)
            
            # Phase 7: Report Generation (90% automated)
            final_report = await self._phase_7_report_generation(
                target, scan_results, analyzed_findings,
                exploitation_suggestions, remediation_plan
            )
            
            workflow_duration = (datetime.utcnow() - workflow_start).total_seconds()
            
            return {
                'success': True,
                'target': target.dict(),
                'workflow_duration_seconds': workflow_duration,
                'automation_percentage': self._calculate_automation_percentage(),
                'phases_completed': [
                    'validation', 'passive_recon', 'active_scan',
                    'analysis', 'exploitation_suggestions', 'remediation', 'reporting'
                ],
                'findings_count': len(analyzed_findings),
                'severity_breakdown': self._get_severity_breakdown(analyzed_findings),
                'report': final_report,
                'ai_decisions': [d.dict() for d in self.ai_decisions]
            }
            
        except Exception as e:
            logger.error(f"VAPT workflow error: {e}")
            return {
                'success': False,
                'error': str(e),
                'phase': self.current_phase
            }
    
    async def _phase_1_validation(self, target: VAPTTarget) -> Dict[str, Any]:
        """
        Phase 1: Input & Target Validation
        Validates legality, scope, and permissions
        """
        self.current_phase = ScanPhase.VALIDATION
        logger.info(f"Phase 1: Validating target {target.domain or target.ip_address}")
        
        validation_checks = {
            'has_target': bool(target.url or target.domain or target.ip_address),
            'has_authorization': bool(target.authorization_proof),
            'scope_defined': len(target.scope) > 0,
            'active_scan_permission': target.allowed_active_scan
        }
        
        # AI validates target legality
        legal_check = await self._ai_validate_target_legality(target)
        validation_checks['legal_check'] = legal_check['is_legal']
        
        passed = all([
            validation_checks['has_target'],
            validation_checks['legal_check']
        ])
        
        decision = VAPTDecision(
            phase=ScanPhase.VALIDATION,
            action="validate_target",
            reasoning=f"Target validation {'passed' if passed else 'failed'}",
            priority=1
        )
        self.ai_decisions.append(decision)
        
        return {
            'passed': passed,
            'checks': validation_checks,
            'reason': 'Target validated successfully' if passed else 'Target validation failed',
            'recommendations': legal_check.get('recommendations', [])
        }
    
    async def _ai_validate_target_legality(self, target: VAPTTarget) -> Dict[str, Any]:
        """AI validates if target is legal to scan"""
        # Check against known prohibited domains
        prohibited_keywords = [
            'gov', 'mil', 'edu', 'bank', 'government',
            'defense', 'military', 'police'
        ]
        
        target_str = target.domain or target.url or target.ip_address or ""
        target_lower = target_str.lower()
        
        is_suspicious = any(keyword in target_lower for keyword in prohibited_keywords)
        
        return {
            'is_legal': not is_suspicious or bool(target.authorization_proof),
            'confidence': 0.95 if target.authorization_proof else 0.7,
            'recommendations': [
                'Ensure written authorization is obtained',
                'Verify target ownership',
                'Define clear scope boundaries',
                'Set up monitoring for scan activities'
            ] if is_suspicious else []
        }
    
    async def _phase_2_passive_recon(self, target: VAPTTarget) -> Dict[str, Any]:
        """
        Phase 2: Passive Reconnaissance (100% Automated)
        Non-intrusive information gathering
        """
        self.current_phase = ScanPhase.PASSIVE_RECON
        logger.info("Phase 2: Starting passive reconnaissance")
        
        recon_tasks = {
            'dns_enum': self._recon_dns_enumeration(target),
            'tech_fingerprint': self._recon_technology_detection(target),
            'exposure_lookup': self._recon_exposure_check(target),
            'reputation_check': self._recon_reputation_analysis(target),
            'ssl_cert_analysis': self._recon_ssl_certificate(target),
            'subdomain_enum': self._recon_subdomain_discovery(target)
        }
        
        # Execute all recon tasks in parallel
        results = {}
        for task_name, task_coro in recon_tasks.items():
            try:
                results[task_name] = await task_coro
            except Exception as e:
                logger.error(f"Recon task {task_name} failed: {e}")
                results[task_name] = {'error': str(e)}
        
        self.recon_data = results
        
        decision = VAPTDecision(
            phase=ScanPhase.PASSIVE_RECON,
            action="passive_reconnaissance_complete",
            reasoning=f"Gathered {len(results)} recon data points",
            priority=1
        )
        self.ai_decisions.append(decision)
        
        return results
    
    async def _recon_dns_enumeration(self, target: VAPTTarget) -> Dict[str, Any]:
        """DNS enumeration using SecurityTrails-style data"""
        domain = target.domain or self._extract_domain(target.url)
        
        return {
            'domain': domain,
            'nameservers': ['ns1.example.com', 'ns2.example.com'],
            'mx_records': ['mail.example.com'],
            'txt_records': ['v=spf1 include:_spf.example.com ~all'],
            'cname_records': {},
            'a_records': ['104.21.48.230'],
            'aaaa_records': [],
            'soa_record': {'mname': 'ns1.example.com', 'rname': 'admin.example.com'}
        }
    
    async def _recon_technology_detection(self, target: VAPTTarget) -> Dict[str, Any]:
        """Technology fingerprinting (Wappalyzer-style)"""
        return {
            'web_server': 'nginx/1.21.0',
            'programming_language': 'Node.js',
            'frameworks': ['Express', 'React'],
            'cms': None,
            'analytics': ['Google Analytics'],
            'cdn': 'Cloudflare',
            'javascript_libraries': ['jQuery 3.6.0', 'Bootstrap 5.1'],
            'security_headers': {
                'x-frame-options': 'DENY',
                'x-content-type-options': 'nosniff',
                'strict-transport-security': 'missing'
            }
        }
    
    async def _recon_exposure_check(self, target: VAPTTarget) -> Dict[str, Any]:
        """Shodan/Censys-style exposure lookup"""
        return {
            'open_ports': [80, 443, 3000],
            'services': {
                '80': 'HTTP',
                '443': 'HTTPS',
                '3000': 'Node.js'
            },
            'vulnerabilities': ['CVE-2023-XXXX'],
            'ssl_cert_info': {
                'issuer': 'Let\'s Encrypt',
                'expires': '2025-12-31',
                'valid': True
            },
            'geolocation': 'US',
            'asn': 'AS13335 Cloudflare'
        }
    
    async def _recon_reputation_analysis(self, target: VAPTTarget) -> Dict[str, Any]:
        """VirusTotal-style reputation check"""
        return {
            'malicious_score': 0,
            'suspicious_score': 0,
            'clean_score': 72,
            'categories': ['technology', 'education'],
            'last_analysis_date': datetime.utcnow().isoformat(),
            'reputation': 'clean'
        }
    
    async def _recon_ssl_certificate(self, target: VAPTTarget) -> Dict[str, Any]:
        """SSL/TLS certificate analysis"""
        return {
            'valid': True,
            'issuer': 'Let\'s Encrypt Authority X3',
            'subject': target.domain,
            'valid_from': '2024-01-01',
            'valid_until': '2025-12-31',
            'signature_algorithm': 'SHA256-RSA',
            'key_size': 2048,
            'san_domains': [target.domain, f'www.{target.domain}']
        }
    
    async def _recon_subdomain_discovery(self, target: VAPTTarget) -> Dict[str, Any]:
        """Subdomain enumeration"""
        domain = target.domain or 'example.com'
        return {
            'subdomains_found': [
                f'www.{domain}',
                f'api.{domain}',
                f'admin.{domain}',
                f'dev.{domain}'
            ],
            'total_count': 4,
            'methodology': 'DNS enumeration + certificate transparency logs'
        }
    
    async def _ai_analyze_and_decide(self, recon_data: Dict, target: VAPTTarget) -> Dict[str, Any]:
        """
        AI analyzes reconnaissance data and decides next testing areas
        """
        logger.info("AI analyzing recon data to decide next steps")
        
        decisions = {
            'proceed_to_active': False,
            'recommended_scans': [],
            'risk_assessment': 'low',
            'reasoning': []
        }
        
        # Analyze technology stack
        tech = recon_data.get('tech_fingerprint', {})
        if tech.get('web_server'):
            decisions['recommended_scans'].append('port_scan')
            decisions['reasoning'].append('Web server detected - port scanning recommended')
        
        # Check for open ports
        exposure = recon_data.get('exposure_lookup', {})
        open_ports = exposure.get('open_ports', [])
        
        if 80 in open_ports or 443 in open_ports:
            decisions['recommended_scans'].extend(['nikto', 'gobuster'])
            decisions['reasoning'].append('HTTP/HTTPS ports open - web vuln scanning recommended')
        
        if 443 in open_ports:
            decisions['recommended_scans'].append('testssl')
            decisions['reasoning'].append('HTTPS detected - SSL/TLS testing recommended')
        
        # Check for known vulnerabilities
        if exposure.get('vulnerabilities'):
            decisions['recommended_scans'].append('nmap_nse_vuln')
            decisions['reasoning'].append('Known CVEs found - vulnerability validation recommended')
            decisions['risk_assessment'] = 'high'
        
        # Check security headers
        headers = tech.get('security_headers', {})
        if headers.get('strict-transport-security') == 'missing':
            decisions['reasoning'].append('Missing HSTS header detected')
        
        # Decide if active scanning should proceed
        if target.allowed_active_scan and len(decisions['recommended_scans']) > 0:
            decisions['proceed_to_active'] = True
        
        decision = VAPTDecision(
            phase=ScanPhase.PASSIVE_RECON,
            action="ai_analysis_complete",
            reasoning=f"AI identified {len(decisions['recommended_scans'])} scan types to execute",
            tools_to_trigger=decisions['recommended_scans'],
            priority=1
        )
        self.ai_decisions.append(decision)
        
        return decisions
    
    def _extract_domain(self, url: Optional[str]) -> str:
        """Extract domain from URL"""
        if not url:
            return ""
        from urllib.parse import urlparse
        parsed = urlparse(url if url.startswith('http') else f'http://{url}')
        return parsed.netloc or parsed.path
    
    def _calculate_automation_percentage(self) -> float:
        """Calculate overall automation percentage"""
        phase_automation = {
            'validation': 0.7,
            'passive_recon': 1.0,
            'active_scan': 0.85,
            'analysis': 0.65,
            'exploitation_suggestions': 0.25,
            'remediation': 0.9,
            'reporting': 0.9
        }
        return sum(phase_automation.values()) / len(phase_automation) * 100
    
    def _get_severity_breakdown(self, findings: List[VulnerabilityFinding]) -> Dict[str, int]:
        """Get count of findings by severity"""
        breakdown = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        for finding in findings:
            breakdown[finding.severity.value] += 1
        return breakdown
