"""
Compliance Mapping Service
Week 9-10: Map vulnerabilities to compliance frameworks

Supported Frameworks:
- NIST Cybersecurity Framework
- ISO 27001:2013
- PCI-DSS 4.0
- HIPAA Security Rule
- CIS Controls v8
"""
import logging
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum


logger = logging.getLogger(__name__)


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks"""
    NIST_CSF = "NIST Cybersecurity Framework"
    ISO_27001 = "ISO 27001:2013"
    PCI_DSS = "PCI-DSS 4.0"
    HIPAA = "HIPAA Security Rule"
    CIS_CONTROLS = "CIS Controls v8"


class ComplianceMapper:
    """Map vulnerabilities to compliance controls"""
    
    def __init__(self):
        """Initialize compliance mapper"""
        self._load_control_mappings()
        logger.info("Compliance Mapper initialized")
    
    def _load_control_mappings(self):
        """Load control mappings for each framework"""
        
        # NIST Cybersecurity Framework
        self.nist_csf_controls = {
            'ID.AM': {
                'name': 'Asset Management',
                'description': 'The data, personnel, devices, systems, and facilities that enable the organization to achieve business purposes are identified and managed',
                'related_cwe': ['CWE-200', 'CWE-668']
            },
            'ID.RA': {
                'name': 'Risk Assessment',
                'description': 'The organization understands cybersecurity risk to organizational operations',
                'related_cwe': ['CWE-1004']
            },
            'PR.AC': {
                'name': 'Access Control',
                'description': 'Access to physical and logical assets and associated facilities is limited to authorized users',
                'related_cwe': ['CWE-287', 'CWE-284', 'CWE-285', 'CWE-862']
            },
            'PR.DS': {
                'name': 'Data Security',
                'description': 'Information and records are managed consistent with risk strategy',
                'related_cwe': ['CWE-311', 'CWE-312', 'CWE-319', 'CWE-327']
            },
            'PR.IP': {
                'name': 'Information Protection Processes',
                'description': 'Security policies, processes, and procedures are maintained',
                'related_cwe': ['CWE-1008']
            },
            'PR.PT': {
                'name': 'Protective Technology',
                'description': 'Technical security solutions are managed to ensure security and resilience',
                'related_cwe': ['CWE-20', 'CWE-79', 'CWE-89', 'CWE-78']
            },
            'DE.CM': {
                'name': 'Security Continuous Monitoring',
                'description': 'The information system and assets are monitored to identify cybersecurity events',
                'related_cwe': ['CWE-778', 'CWE-223']
            },
            'RS.MI': {
                'name': 'Mitigation',
                'description': 'Activities are performed to prevent expansion of an event',
                'related_cwe': ['CWE-916']
            }
        }
        
        # ISO 27001:2013 Controls
        self.iso_27001_controls = {
            'A.9.1': {
                'name': 'Access Control Policy',
                'description': 'Business requirement of access control',
                'related_cwe': ['CWE-284', 'CWE-285']
            },
            'A.9.2': {
                'name': 'User Access Management',
                'description': 'User registration and de-registration, user access provisioning',
                'related_cwe': ['CWE-287', 'CWE-262']
            },
            'A.9.4': {
                'name': 'System and Application Access Control',
                'description': 'Information access restriction, secure log-on procedures',
                'related_cwe': ['CWE-287', 'CWE-306']
            },
            'A.10.1': {
                'name': 'Cryptographic Controls',
                'description': 'Policy on use of cryptographic controls',
                'related_cwe': ['CWE-327', 'CWE-328', 'CWE-326']
            },
            'A.12.2': {
                'name': 'Protection from Malware',
                'description': 'Controls against malware',
                'related_cwe': ['CWE-506']
            },
            'A.12.6': {
                'name': 'Technical Vulnerability Management',
                'description': 'Management of technical vulnerabilities',
                'related_cwe': ['CWE-1035']
            },
            'A.14.2': {
                'name': 'Security in Development',
                'description': 'Secure development policy, system change control',
                'related_cwe': ['CWE-20', 'CWE-79', 'CWE-89']
            },
            'A.18.1': {
                'name': 'Compliance with Legal Requirements',
                'description': 'Identification and review of applicable legislation',
                'related_cwe': []
            }
        }
        
        # PCI-DSS 4.0 Requirements
        self.pci_dss_controls = {
            'Req-1': {
                'name': 'Install and Maintain Network Security Controls',
                'description': 'Firewalls and other network security technologies',
                'related_cwe': ['CWE-749']
            },
            'Req-2': {
                'name': 'Apply Secure Configurations',
                'description': 'Apply secure configurations to all system components',
                'related_cwe': ['CWE-1188', 'CWE-16']
            },
            'Req-3': {
                'name': 'Protect Stored Account Data',
                'description': 'Protect stored cardholder data',
                'related_cwe': ['CWE-311', 'CWE-312']
            },
            'Req-4': {
                'name': 'Protect Cardholder Data with Strong Cryptography',
                'description': 'Protect data in transit with strong cryptography',
                'related_cwe': ['CWE-319', 'CWE-327']
            },
            'Req-5': {
                'name': 'Protect All Systems from Malware',
                'description': 'Protect systems and networks from malicious software',
                'related_cwe': ['CWE-506']
            },
            'Req-6': {
                'name': 'Develop and Maintain Secure Systems',
                'description': 'Develop and maintain secure systems and software',
                'related_cwe': ['CWE-20', 'CWE-79', 'CWE-89', 'CWE-78', 'CWE-94']
            },
            'Req-8': {
                'name': 'Identify Users and Authenticate Access',
                'description': 'Identify and authenticate access to system components',
                'related_cwe': ['CWE-287', 'CWE-798']
            },
            'Req-11': {
                'name': 'Test Security of Systems Regularly',
                'description': 'Regularly test security systems and processes',
                'related_cwe': ['CWE-1004']
            }
        }
        
        # HIPAA Security Rule
        self.hipaa_controls = {
            'Sec-164.308': {
                'name': 'Administrative Safeguards',
                'description': 'Security management process, assigned security responsibility',
                'related_cwe': ['CWE-1008']
            },
            'Sec-164.310': {
                'name': 'Physical Safeguards',
                'description': 'Facility access controls, workstation use and security',
                'related_cwe': []
            },
            'Sec-164.312': {
                'name': 'Technical Safeguards',
                'description': 'Access control, audit controls, integrity, transmission security',
                'related_cwe': ['CWE-287', 'CWE-319', 'CWE-778']
            }
        }
        
        # CIS Controls v8
        self.cis_controls = {
            'CIS-1': {
                'name': 'Inventory and Control of Enterprise Assets',
                'description': 'Actively manage hardware devices',
                'related_cwe': []
            },
            'CIS-3': {
                'name': 'Data Protection',
                'description': 'Protect data according to its classification',
                'related_cwe': ['CWE-311', 'CWE-312']
            },
            'CIS-5': {
                'name': 'Account Management',
                'description': 'Use processes and tools to manage accounts',
                'related_cwe': ['CWE-287', 'CWE-284']
            },
            'CIS-6': {
                'name': 'Access Control Management',
                'description': 'Use processes and tools to track/control access',
                'related_cwe': ['CWE-284', 'CWE-285']
            },
            'CIS-7': {
                'name': 'Continuous Vulnerability Management',
                'description': 'Develop a plan to continuously assess and remediate vulnerabilities',
                'related_cwe': ['CWE-1035']
            },
            'CIS-16': {
                'name': 'Application Software Security',
                'description': 'Manage security lifecycle of in-house, hosted, or acquired software',
                'related_cwe': ['CWE-20', 'CWE-79', 'CWE-89']
            }
        }
        
        # CWE to vulnerability type mapping
        self.cwe_to_vuln_type = {
            'CWE-79': 'Cross-Site Scripting (XSS)',
            'CWE-89': 'SQL Injection',
            'CWE-78': 'OS Command Injection',
            'CWE-287': 'Improper Authentication',
            'CWE-284': 'Improper Access Control',
            'CWE-285': 'Improper Authorization',
            'CWE-311': 'Missing Encryption',
            'CWE-319': 'Cleartext Transmission',
            'CWE-327': 'Use of Broken Crypto',
            'CWE-20': 'Improper Input Validation',
            'CWE-200': 'Information Exposure',
            'CWE-502': 'Deserialization',
            'CWE-862': 'Missing Authorization'
        }
    
    def map_vulnerabilities_to_framework(
        self,
        vulnerabilities: List[Dict],
        framework: ComplianceFramework
    ) -> Dict[str, Any]:
        """
        Map vulnerabilities to compliance framework controls
        
        Args:
            vulnerabilities: List of vulnerabilities with CVE/CWE info
            framework: Target compliance framework
            
        Returns:
            Mapping with controls, gaps, compliance rate
        """
        logger.info(f"Mapping {len(vulnerabilities)} vulnerabilities to {framework.value}")
        
        # Get framework controls
        if framework == ComplianceFramework.NIST_CSF:
            controls = self.nist_csf_controls
        elif framework == ComplianceFramework.ISO_27001:
            controls = self.iso_27001_controls
        elif framework == ComplianceFramework.PCI_DSS:
            controls = self.pci_dss_controls
        elif framework == ComplianceFramework.HIPAA:
            controls = self.hipaa_controls
        elif framework == ComplianceFramework.CIS_CONTROLS:
            controls = self.cis_controls
        else:
            raise ValueError(f"Unsupported framework: {framework}")
        
        # Map vulnerabilities to controls
        control_violations = {}
        
        for vuln in vulnerabilities:
            # Extract CWE IDs from vulnerability
            cwe_ids = self._extract_cwe_ids(vuln)
            
            # Find matching controls
            for control_id, control_info in controls.items():
                related_cwes = control_info.get('related_cwe', [])
                
                # Check if vulnerability matches control
                if any(cwe in related_cwes for cwe in cwe_ids):
                    if control_id not in control_violations:
                        control_violations[control_id] = {
                            'control': control_info,
                            'vulnerabilities': [],
                            'severity_counts': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
                        }
                    
                    control_violations[control_id]['vulnerabilities'].append(vuln)
                    severity = vuln.get('severity', 'UNKNOWN')
                    if severity in control_violations[control_id]['severity_counts']:
                        control_violations[control_id]['severity_counts'][severity] += 1
        
        # Calculate compliance metrics
        total_controls = len(controls)
        failed_controls = len(control_violations)
        passed_controls = total_controls - failed_controls
        compliance_rate = (passed_controls / total_controls * 100) if total_controls > 0 else 0
        
        # Build failed controls list
        failed_controls_list = []
        for control_id, violation_info in control_violations.items():
            failed_controls_list.append({
                'id': control_id,
                'name': violation_info['control']['name'],
                'description': violation_info['control']['description'],
                'finding_count': len(violation_info['vulnerabilities']),
                'severity_counts': violation_info['severity_counts'],
                'critical_findings': violation_info['severity_counts']['CRITICAL'],
                'high_findings': violation_info['severity_counts']['HIGH']
            })
        
        # Sort by severity (critical first)
        failed_controls_list.sort(
            key=lambda x: (x['critical_findings'], x['high_findings']),
            reverse=True
        )
        
        return {
            'framework': framework.value,
            'timestamp': datetime.now().isoformat(),
            'total_controls': total_controls,
            'passed_controls': passed_controls,
            'failed_controls_count': failed_controls,
            'compliance_rate': round(compliance_rate, 2),
            'controls': list(controls.keys()),
            'failed_controls': failed_controls_list,
            'control_violations': control_violations,
            'total_vulnerabilities': len(vulnerabilities),
            'recommendations': self._generate_recommendations(failed_controls_list, framework)
        }
    
    def _extract_cwe_ids(self, vulnerability: Dict) -> List[str]:
        """Extract CWE IDs from vulnerability data"""
        cwe_ids = []
        
        # Check direct CWE field
        if 'cwe_id' in vulnerability:
            cwe_ids.append(vulnerability['cwe_id'])
        
        # Check description for CWE references
        description = vulnerability.get('description', '')
        vulnerability_type = vulnerability.get('vulnerability_type', '')
        
        # Map vulnerability types to CWEs
        if 'SQL' in description or 'SQL' in vulnerability_type:
            cwe_ids.append('CWE-89')
        if 'XSS' in description or 'Cross-Site Scripting' in vulnerability_type:
            cwe_ids.append('CWE-79')
        if 'authentication' in description.lower():
            cwe_ids.append('CWE-287')
        if 'encryption' in description.lower() or 'cleartext' in description.lower():
            cwe_ids.append('CWE-319')
        if 'command injection' in description.lower():
            cwe_ids.append('CWE-78')
        if 'access control' in description.lower():
            cwe_ids.append('CWE-284')
        
        return list(set(cwe_ids))
    
    def _generate_recommendations(
        self,
        failed_controls: List[Dict],
        framework: ComplianceFramework
    ) -> List[str]:
        """Generate compliance recommendations"""
        recommendations = []
        
        # Priority recommendations based on critical/high findings
        critical_controls = [c for c in failed_controls if c['critical_findings'] > 0]
        
        if critical_controls:
            recommendations.append(
                f"URGENT: Address {len(critical_controls)} controls with critical findings immediately"
            )
        
        # Framework-specific recommendations
        if framework == ComplianceFramework.NIST_CSF:
            recommendations.extend([
                "Implement continuous monitoring for security events (DE.CM)",
                "Review and update access control policies (PR.AC)",
                "Conduct regular risk assessments (ID.RA)"
            ])
        elif framework == ComplianceFramework.ISO_27001:
            recommendations.extend([
                "Document and implement secure development lifecycle (A.14.2)",
                "Establish vulnerability management program (A.12.6)",
                "Implement cryptographic controls policy (A.10.1)"
            ])
        elif framework == ComplianceFramework.PCI_DSS:
            recommendations.extend([
                "Ensure all cardholder data is encrypted (Req-3)",
                "Implement secure coding practices (Req-6)",
                "Conduct quarterly vulnerability scans (Req-11)"
            ])
        elif framework == ComplianceFramework.HIPAA:
            recommendations.extend([
                "Implement technical safeguards for ePHI (164.312)",
                "Establish audit controls and logging (164.312)",
                "Encrypt data in transit (164.312)"
            ])
        
        # Generic recommendations
        recommendations.extend([
            "Prioritize remediation based on CVSS scores and exploitability",
            "Implement defense-in-depth security architecture",
            "Conduct regular security awareness training",
            "Maintain up-to-date security documentation"
        ])
        
        return recommendations
    
    def generate_gap_analysis(
        self,
        current_state: Dict[str, Any],
        framework: ComplianceFramework
    ) -> Dict[str, Any]:
        """
        Generate gap analysis report
        
        Args:
            current_state: Current compliance mapping
            framework: Target framework
            
        Returns:
            Gap analysis with priorities
        """
        gaps = []
        
        for control in current_state.get('failed_controls', []):
            gap = {
                'control_id': control['id'],
                'control_name': control['name'],
                'gap_severity': self._calculate_gap_severity(control),
                'findings': control['finding_count'],
                'remediation_priority': self._calculate_priority(control),
                'estimated_effort': self._estimate_effort(control)
            }
            gaps.append(gap)
        
        # Sort by priority
        gaps.sort(key=lambda x: x['remediation_priority'])
        
        return {
            'framework': framework.value,
            'total_gaps': len(gaps),
            'critical_gaps': sum(1 for g in gaps if g['gap_severity'] == 'Critical'),
            'high_gaps': sum(1 for g in gaps if g['gap_severity'] == 'High'),
            'gaps': gaps,
            'remediation_roadmap': self._create_roadmap(gaps)
        }
    
    def _calculate_gap_severity(self, control: Dict) -> str:
        """Calculate gap severity based on findings"""
        if control['critical_findings'] > 0:
            return 'Critical'
        elif control['high_findings'] > 0:
            return 'High'
        elif control['finding_count'] > 5:
            return 'Medium'
        else:
            return 'Low'
    
    def _calculate_priority(self, control: Dict) -> int:
        """Calculate remediation priority (lower is higher priority)"""
        priority = 0
        priority += control['critical_findings'] * 100
        priority += control['high_findings'] * 10
        priority += control['finding_count']
        return -priority  # Negative for reverse sort
    
    def _estimate_effort(self, control: Dict) -> str:
        """Estimate remediation effort"""
        findings = control['finding_count']
        if findings <= 2:
            return 'Low (1-2 weeks)'
        elif findings <= 5:
            return 'Medium (3-4 weeks)'
        else:
            return 'High (1-2 months)'
    
    def _create_roadmap(self, gaps: List[Dict]) -> List[Dict]:
        """Create remediation roadmap"""
        roadmap = []
        
        # Phase 1: Critical gaps (immediate)
        critical = [g for g in gaps if g['gap_severity'] == 'Critical']
        if critical:
            roadmap.append({
                'phase': 'Phase 1 - Critical (Immediate)',
                'duration': '1-2 weeks',
                'controls': [g['control_id'] for g in critical]
            })
        
        # Phase 2: High priority (30 days)
        high = [g for g in gaps if g['gap_severity'] == 'High']
        if high:
            roadmap.append({
                'phase': 'Phase 2 - High Priority (30 days)',
                'duration': '3-4 weeks',
                'controls': [g['control_id'] for g in high]
            })
        
        # Phase 3: Medium/Low (90 days)
        medium_low = [g for g in gaps if g['gap_severity'] in ['Medium', 'Low']]
        if medium_low:
            roadmap.append({
                'phase': 'Phase 3 - Ongoing (90 days)',
                'duration': '2-3 months',
                'controls': [g['control_id'] for g in medium_low]
            })
        
        return roadmap


# Global singleton
_compliance_mapper: Optional[ComplianceMapper] = None


def get_compliance_mapper() -> ComplianceMapper:
    """Get compliance mapper singleton"""
    global _compliance_mapper
    if _compliance_mapper is None:
        _compliance_mapper = ComplianceMapper()
    return _compliance_mapper
