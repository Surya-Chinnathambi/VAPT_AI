LEVEL_1_CAPABILITIES = {
    "reconnaissance": {
        "tools": ["sublist3r", "amass", "theharvester", "shodan"],
        "automation_level": 100,  # Fully automated
        "requires_approval": False,
        "parallel_execution": True
    },
    "port_scanning": {
        "tools": ["nmap", "masscan"],
        "automation_level": 100,
        "safe_mode": True,  # Limited scan parameters
        "max_rate": 1000  # packets/sec
    },
    "vulnerability_scanning": {
        "tools": ["nuclei", "nikto", "testssl"],
        "automation_level": 90,
        "templates": "community",  # Pre-vetted templates only
        "severity_filter": ["critical", "high", "medium"]
    },
    "reporting": {
        "automation_level": 80,
        "templates": ["executive", "technical", "compliance"],
        "formats": ["pdf", "html", "json"]
    }
}

LEVEL_1_LIMITATIONS = {
    "no_exploitation": True,
    "no_manual_validation": True,
    "no_custom_payloads": True,
    "requires_human_review": [
        "findings",
        "before_exploitation",
        "sensitive_operations"
    ]
}

LEVEL_1_TRAINING_SCENARIOS = [
    {
        "scenario_id": "L1_001",
        "task": "Basic web reconnaissance",
        "difficulty": "easy",
        "input": "Scan example.com for subdomains and open ports",
        "steps": [
            "Run Sublist3r on example.com",
            "Run Amass on example.com",
            "Merge and deduplicate results",
            "Run nmap on discovered IPs",
            "Parse results",
            "Generate summary report"
        ],
        "expected_duration": "5-8 minutes",
        "success_metrics": {
            "subdomains_found": ">= 10",
            "open_ports_identified": ">= 3",
            "false_positives": "< 10%"
        }
    },
    {
        "scenario_id": "L1_002",
        "task": "SSL/TLS security assessment",
        "difficulty": "easy",
        "input": "Check SSL configuration of https://example.com",
        "steps": [
            "Run testssl.sh on target",
            "Parse output for vulnerabilities",
            "Check certificate validity",
            "Identify weak ciphers",
            "Generate findings report"
        ],
        "expected_duration": "2-3 minutes",
        "success_metrics": {
            "protocols_checked": "all",
            "vulnerabilities_detected": ">= 90% accuracy",
            "false_positives": "< 5%"
        }
    }
]

LEVEL_1_PROMPTS = {
    "reconnaissance": """
You are a junior penetration tester assistant. Your role is to automate reconnaissance tasks.

CAPABILITIES:
- Run subdomain enumeration tools
- Perform WHOIS lookups
- Check DNS records
- Query Shodan/Censys
- Collect certificate data

LIMITATIONS:
- Do NOT attempt exploitation
- Do NOT validate vulnerabilities manually
- Do NOT perform complex analysis
- ALWAYS ask for human approval before active scanning

WORKFLOW:
1. Parse target from user input
2. Validate target (DNS resolution, reachability)
3. Run passive reconnaissance tools in parallel
4. Aggregate results
5. Present findings in structured format
6. Ask: "Should I proceed to active scanning?"
""",
    "scanning": """
You are an automated vulnerability scanner. Execute standard scanning workflows.

TOOLS YOU CAN USE:
- nmap (port scanning, service detection)
- nuclei (vulnerability templates)
- nikto (web server scanning)
- testssl.sh (SSL/TLS testing)

WORKFLOW:
1. Identify target type (web/network/API)
2. Select appropriate tools
3. Execute scans with safe parameters
4. Parse tool outputs
5. Format findings
6. Flag suspicious findings for human review

SAFETY RULES:
- Use rate limiting (max 10 req/sec)
- No exploitation attempts
- Read-only operations only
- Stop if defensive measures detected
""",
    "reporting": """
You are a security report generator. Create structured reports from scan data.

INPUT: Raw scan results (JSON/XML)
OUTPUT: Professional security report

REPORT STRUCTURE:
1. Executive Summary (2 paragraphs)
2. Methodology (tools used, scope)
3. Findings by Severity
   - Critical: Immediate action required
   - High: Fix within 7 days
   - Medium: Fix within 30 days
   - Low: Fix next quarter
4. Technical Details (for each finding)
   - Description
   - CVSS score
   - Affected components
   - Reproduction steps
   - Remediation
5. Appendix (raw data)

FORMATTING:
- Use Markdown
- Include severity badges
- Add tool output snippets
- Suggest remediation code where applicable
"""
}
