from .level1_config import LEVEL_1_CAPABILITIES

LEVEL_2_CAPABILITIES = {
    **LEVEL_1_CAPABILITIES,  # Inherit from Level 1
    
    "vulnerability_validation": {
        "automation_level": 70,
        "methods": [
            "multi_tool_confirmation",
            "cve_cross_reference",
            "exploit_availability_check",
            "safe_poc_testing"
        ],
        "confidence_threshold": 0.85  # 85% confidence required
    },
    
    "basic_exploitation": {
        "automation_level": 50,
        "allowed_tools": ["sqlmap", "xsstrike", "hydra", "metasploit"],
        "safe_mode": True,
        "requires_approval": True,
        "operations": [
            "read_only_sql_injection",
            "reflected_xss_demo",
            "default_credential_testing",
            "known_cve_poc"
        ],
        "forbidden_operations": [
            "data_modification",
            "privilege_escalation",
            "persistent_access",
            "data_exfiltration"
        ]
    },
    
    "intelligent_prioritization": {
        "automation_level": 80,
        "factors": {
            "cvss_score": 0.30,
            "exploitability": 0.25,
            "asset_criticality": 0.25,
            "business_impact": 0.20
        },
        "output": "ranked_remediation_roadmap"
    },
    
    "advanced_reporting": {
        "automation_level": 85,
        "features": [
            "executive_summary_with_business_impact",
            "technical_deep_dive",
            "compliance_mapping",
            "remediation_code_snippets",
            "attack_path_visualization"
        ]
    }
}

LEVEL_2_PROMPTS = {
    "validation": """
You are a security analyst with vulnerability validation expertise.

CAPABILITIES:
- Validate scan findings for false positives
- Cross-reference with CVE databases
- Check exploit availability
- Test PoC exploits in safe mode
- Calculate actual risk scores

VALIDATION WORKFLOW:
1. Receive scan finding
2. Analyze with multiple tools (confirm/deny)
3. Search CVE database for details
4. Check Exploit-DB for public exploits
5. Assess exploitability (Low/Medium/High)
6. Calculate business impact
7. Provide validated finding with confidence score
""",
    "exploitation": """
You are an exploitation specialist (Level 2). Perform safe exploitation.

ALLOWED EXPLOITATION:
- SQL injection (SQLMap automation)
- XSS (automated payload testing)
- Authentication bypass (default credentials, auth flaws)
- Command injection (safe PoC only)
- File upload vulnerabilities (non-malicious files)
- Known CVEs with Metasploit modules

EXPLOITATION RULES:
1. ALWAYS read-only operations (no data modification)
2. ALWAYS get human approval before exploitation
3. ALWAYS document every step with screenshots
4. NEVER use destructive payloads
5. STOP if defensive measures activate
6. ALWAYS clean up after testing
""",
    "prioritization": """
You are a risk analyst. Prioritize vulnerabilities for remediation.

PRIORITIZATION FACTORS:
1. CVSS Base Score (0-10)
2. Exploitability (Public exploit available?)
3. Asset Criticality (Production? Customer data?)
4. Business Impact (Revenue? Reputation? Compliance?)
5. Remediation Effort (Hours? Days? Weeks?)
6. Attack Complexity (Low? Medium? High?)


SCORING ALGORITHM:
Risk Score = (CVSS * 0.3) + (Exploitability * 0.25) + (Asset Criticality * 0.25) + (Business Impact * 0.2)
"""
}

LEVEL_2_TRAINING_SCENARIOS = [
    {
        "scenario_id": "L2_001",
        "task": "Validate and exploit SQL injection",
        "difficulty": "medium",
        "input": "Potential SQL injection in /products?id=1",
        "steps": [
            "Test with manual payloads (', 1=1, 1=2)",
            "Confirm with SQLMap",
            "Identify injection type (boolean-based blind)",
            "Extract database name",
            "Extract one table name",
            "Demonstrate impact (1 row extraction)",
            "Stop exploitation",
            "Document findings",
            "Provide remediation code"
        ],
        "expected_duration": "15-20 minutes",
        "success_metrics": {
            "validation_accuracy": ">= 95%",
            "exploitation_success": ">= 80%",
            "false_positives": "< 5%",
            "documentation_completeness": "100%"
        }
    },
    {
        "scenario_id": "L2_002",
        "task": "Prioritize 20 vulnerabilities for remediation",
        "difficulty": "medium",
        "input": "List of 20 findings with varying severities",
        "steps": [
            "Calculate CVSS scores",
            "Check exploit availability",
            "Assess asset criticality",
            "Estimate business impact",
            "Calculate risk scores",
            "Rank vulnerabilities",
            "Generate remediation roadmap",
            "Estimate fix times",
            "Provide business justification"
        ],
        "expected_duration": "10-15 minutes",
        "success_metrics": {
            "prioritization_accuracy": ">= 90%",
            "matches_human_expert": ">= 85%",
            "business_context": "present"
        }
    }
]
