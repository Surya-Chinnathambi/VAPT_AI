"""
Compliance Mapping Engine
Maps vulnerabilities to compliance frameworks
"""
import json
import logging
from typing import List, Dict, Any
from services.vector_db_service import get_vector_db

logger = logging.getLogger(__name__)

# Compliance framework requirements
COMPLIANCE_FRAMEWORKS = {
    "OWASP_TOP10": {
        "name": "OWASP Top 10 2021",
        "requirements": {
            "A01": "Broken Access Control",
            "A02": "Cryptographic Failures",
            "A03": "Injection",
            "A04": "Insecure Design",
            "A05": "Security Misconfiguration",
            "A06": "Vulnerable and Outdated Components",
            "A07": "Identification and Authentication Failures",
            "A08": "Software and Data Integrity Failures",
            "A09": "Security Logging and Monitoring Failures",
            "A10": "Server-Side Request Forgery (SSRF)"
        }
    },
    "PCI_DSS": {
        "name": "PCI DSS 4.0",
        "requirements": {
            "1": "Install and Maintain Network Security Controls",
            "2": "Apply Secure Configurations",
            "3": "Protect Stored Account Data",
            "4": "Protect Cardholder Data with Encryption",
            "5": "Protect Systems Against Malware",
            "6": "Develop and Maintain Secure Systems",
            "7": "Restrict Access by Business Need to Know",
            "8": "Identify Users and Authenticate Access",
            "9": "Restrict Physical Access",
            "10": "Log and Monitor All Access",
            "11": "Test Security of Systems Regularly",
            "12": "Support Information Security with Policies"
        }
    },
    "HIPAA": {
        "name": "HIPAA Security Rule",
        "requirements": {
            "164.308": "Administrative Safeguards",
            "164.310": "Physical Safeguards",
            "164.312": "Technical Safeguards",
            "164.314": "Organizational Requirements",
            "164.316": "Policies and Procedures"
        }
    },
    "ISO_27001": {
        "name": "ISO/IEC 27001:2022",
        "requirements": {
            "A.5": "Organizational Controls",
            "A.6": "People Controls",
            "A.7": "Physical Controls",
            "A.8": "Technological Controls"
        }
    },
    "NIST_CSF": {
        "name": "NIST Cybersecurity Framework",
        "requirements": {
            "ID": "Identify",
            "PR": "Protect",
            "DE": "Detect",
            "RS": "Respond",
            "RC": "Recover"
        }
    }
}

class ComplianceEngine:
    def __init__(self):
        """Initialize compliance engine"""
        try:
            self.vector_db = get_vector_db()
            self.has_vector_db = True
        except:
            self.has_vector_db = False
            logger.warning("Vector DB not available, using rule-based mapping")
    
    def map_vulnerability_to_frameworks(
        self,
        vulnerability: Dict[str, Any],
        frameworks: List[str] = None
    ) -> Dict[str, List[str]]:
        """
        Map a vulnerability to compliance framework requirements
        
        Args:
            vulnerability: Vulnerability data
            frameworks: List of framework codes to check
        
        Returns:
            Dict mapping framework codes to violated requirements
        """
        if frameworks is None:
            frameworks = list(COMPLIANCE_FRAMEWORKS.keys())
        
        mappings = {}
        
        for framework_code in frameworks:
            if framework_code not in COMPLIANCE_FRAMEWORKS:
                continue
            
            framework = COMPLIANCE_FRAMEWORKS[framework_code]
            violated_requirements = []
            
            # Use vector search if available
            if self.has_vector_db:
                violated_requirements = self._vector_search_mapping(
                    vulnerability,
                    framework_code
                )
            else:
                # Fallback to rule-based mapping
                violated_requirements = self._rule_based_mapping(
                    vulnerability,
                    framework_code
                )
            
            if violated_requirements:
                mappings[framework['name']] = violated_requirements
        
        return mappings
    
    def _vector_search_mapping(
        self,
        vulnerability: Dict[str, Any],
        framework_code: str
    ) -> List[str]:
        """Use vector search to find relevant requirements"""
        try:
            description = vulnerability.get('description', '')
            if not description:
                return []
            
            results = self.vector_db.search_compliance(
                query=description,
                framework_code=framework_code,
                n_results=3
            )
            
            requirements = []
            for i in range(len(results['ids'])):
                if results['distances'][i] < 0.3:  # Relevance threshold
                    req_id = results['metadatas'][i]['requirement_id']
                    req_text = results['documents'][i]
                    requirements.append(f"{req_id}: {req_text[:100]}...")
            
            return requirements
            
        except Exception as e:
            logger.error(f"Vector search mapping failed: {e}")
            return []
    
    def _rule_based_mapping(
        self,
        vulnerability: Dict[str, Any],
        framework_code: str
    ) -> List[str]:
        """Rule-based mapping when vector search unavailable"""
        vuln_type = vulnerability.get('type', '').lower()
        description = vulnerability.get('description', '').lower()
        severity = vulnerability.get('severity', '').lower()
        
        requirements = []
        
        if framework_code == "OWASP_TOP10":
            if 'sql injection' in description or 'xss' in description:
                requirements.append("A03: Injection")
            if 'authentication' in description or 'session' in description:
                requirements.append("A07: Identification and Authentication Failures")
            if 'encryption' in description or 'tls' in description:
                requirements.append("A02: Cryptographic Failures")
            if 'configuration' in description or 'default' in description:
                requirements.append("A05: Security Misconfiguration")
            if 'outdated' in description or 'vulnerable' in description:
                requirements.append("A06: Vulnerable and Outdated Components")
            if 'logging' in description or 'monitoring' in description:
                requirements.append("A09: Security Logging and Monitoring Failures")
        
        elif framework_code == "PCI_DSS":
            if any(port in description for port in ['21', '22', '23', '3389']):
                requirements.append("1: Install and Maintain Network Security Controls")
            if 'default' in description or 'configuration' in description:
                requirements.append("2: Apply Secure Configurations")
            if 'encryption' in description:
                requirements.append("4: Protect Cardholder Data with Encryption")
            if 'patch' in description or 'update' in description:
                requirements.append("6: Develop and Maintain Secure Systems")
            if 'logging' in description:
                requirements.append("10: Log and Monitor All Access")
            if severity in ['critical', 'high']:
                requirements.append("11: Test Security of Systems Regularly")
        
        elif framework_code == "HIPAA":
            if 'access control' in description or 'authentication' in description:
                requirements.append("164.308: Administrative Safeguards")
            if 'encryption' in description or 'transmission' in description:
                requirements.append("164.312: Technical Safeguards")
        
        elif framework_code == "ISO_27001":
            if 'access' in description or 'authentication' in description:
                requirements.append("A.5: Organizational Controls")
            if 'encryption' in description or 'cryptographic' in description:
                requirements.append("A.8: Technological Controls")
        
        elif framework_code == "NIST_CSF":
            requirements.append("ID: Identify")
            if 'vulnerability' in description:
                requirements.append("PR: Protect")
            if 'detection' in description or 'monitoring' in description:
                requirements.append("DE: Detect")
        
        return requirements
    
    def generate_compliance_report(
        self,
        vulnerabilities: List[Dict[str, Any]],
        frameworks: List[str] = None
    ) -> Dict[str, Any]:
        """
        Generate comprehensive compliance report
        
        Args:
            vulnerabilities: List of vulnerabilities
            frameworks: Frameworks to assess against
        
        Returns:
            Compliance assessment report
        """
        if not frameworks:
            frameworks = list(COMPLIANCE_FRAMEWORKS.keys())
        
        report = {
            "assessed_frameworks": [
                COMPLIANCE_FRAMEWORKS[code]["name"] 
                for code in frameworks if code in COMPLIANCE_FRAMEWORKS
            ],
            "total_vulnerabilities": len(vulnerabilities),
            "framework_violations": {},
            "compliance_score": {},
            "priority_actions": []
        }
        
        # Map all vulnerabilities
        all_violations = {code: set() for code in frameworks}
        
        for vuln in vulnerabilities:
            mappings = self.map_vulnerability_to_frameworks(vuln, frameworks)
            
            for framework_name, requirements in mappings.items():
                # Find framework code
                for code, fw in COMPLIANCE_FRAMEWORKS.items():
                    if fw['name'] == framework_name:
                        all_violations[code].update(requirements)
                        break
        
        # Calculate compliance scores
        for code in frameworks:
            if code not in COMPLIANCE_FRAMEWORKS:
                continue
            
            framework = COMPLIANCE_FRAMEWORKS[code]
            total_requirements = len(framework['requirements'])
            violated_count = len(all_violations[code])
            
            compliance_percentage = (
                (total_requirements - violated_count) / total_requirements * 100
                if total_requirements > 0 else 100
            )
            
            report['framework_violations'][framework['name']] = list(all_violations[code])
            report['compliance_score'][framework['name']] = round(compliance_percentage, 2)
        
        # Generate priority actions
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'critical']
        high_vulns = [v for v in vulnerabilities if v.get('severity') == 'high']
        
        if critical_vulns:
            report['priority_actions'].append(
                f"URGENT: Address {len(critical_vulns)} critical vulnerabilities immediately"
            )
        
        if high_vulns:
            report['priority_actions'].append(
                f"High Priority: Fix {len(high_vulns)} high-severity vulnerabilities within 7 days"
            )
        
        # Add framework-specific actions
        for code, violations in all_violations.items():
            if violations and code in COMPLIANCE_FRAMEWORKS:
                framework = COMPLIANCE_FRAMEWORKS[code]
                report['priority_actions'].append(
                    f"Review {framework['name']} compliance: {len(violations)} requirement(s) affected"
                )
        
        return report
    
    def get_framework_info(self, framework_code: str) -> Dict[str, Any]:
        """Get information about a compliance framework"""
        if framework_code in COMPLIANCE_FRAMEWORKS:
            return COMPLIANCE_FRAMEWORKS[framework_code]
        return None
    
    def list_frameworks(self) -> List[Dict[str, str]]:
        """List all available frameworks"""
        return [
            {
                "code": code,
                "name": framework["name"],
                "requirement_count": len(framework["requirements"])
            }
            for code, framework in COMPLIANCE_FRAMEWORKS.items()
        ]

# Global instance
_compliance_engine = None

def get_compliance_engine() -> ComplianceEngine:
    """Get or create compliance engine instance"""
    global _compliance_engine
    if _compliance_engine is None:
        _compliance_engine = ComplianceEngine()
    return _compliance_engine
