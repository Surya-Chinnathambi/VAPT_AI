"""
AI VAPT Training Scenario Generator
Generates comprehensive training scenarios for all 3 levels
"""

def generate_level1_scenarios():
    """Generate 50 Level 1 (Basic) training scenarios"""
    scenarios = []
    
    # RECONNAISSANCE SCENARIOS (15 scenarios)
    recon_targets = [
        ("example.com", "corporate website"),
        ("api.example.com", "API endpoint"),
        ("shop.example.com", "e-commerce platform"),
        ("mail.example.com", "email server"),
        ("vpn.example.com", "VPN gateway"),
    ]
    
    for i, (target, desc) in enumerate(recon_targets, 1):
        scenarios.extend([
            {
                "scenario_id": f"L1_R{i:02d}A",
                "task": f"Subdomain enumeration for {desc}",
                "difficulty": "easy",
                "input": f"Enumerate subdomains for {target}",
                "steps": [
                    f"Run Sublist3r on {target}",
                    f"Run Amass on {target}",
                    "Merge and deduplicate results",
                    "Validate subdomains (DNS resolution)",
                    "Generate subdomain report"
                ],
                "expected_duration": "3-5 minutes",
                "expected_output": {
                    "subdomains": ["www", "mail", "ftp", "admin"],
                    "tools_used": ["sublist3r", "amass"],
                    "total_found": ">= 5"
                },
                "success_metrics": {
                    "subdomains_found": ">= 5",
                    "false_positives": "< 10%",
                    "duplicate_removal": "100%"
                }
            },
            {
                "scenario_id": f"L1_R{i:02d}B",
                "task": f"WHOIS and DNS analysis for {desc}",
                "difficulty": "easy",
                "input": f"Gather WHOIS and DNS records for {target}",
                "steps": [
                    f"Run WHOIS lookup on {target}",
                    "Extract registrar information",
                    "Query DNS records (A, MX, TXT, NS)",
                    "Identify name servers",
                    "Generate infrastructure report"
                ],
                "expected_duration": "2-3 minutes",
                "expected_output": {
                    "whois_data": {"registrar": "str", "creation_date": "date"},
                    "dns_records": {"A": [], "MX": [], "TXT": [], "NS": []},
                    "nameservers": []
                },
                "success_metrics": {
                    "data_completeness": ">= 90%",
                    "accuracy": ">= 95%"
                }
            },
            {
                "scenario_id": f"L1_R{i:02d}C",
                "task": f"Certificate transparency search for {desc}",
                "difficulty": "easy",
                "input": f"Search certificate transparency logs for {target}",
                "steps": [
                    f"Query crt.sh for {target}",
                    "Extract SSL certificate details",
                    "Identify additional subdomains",
                    "Check certificate validity",
                    "Generate certificate report"
                ],
                "expected_duration": "2-4 minutes",
                "expected_output": {
                    "certificates_found": ">= 1",
                    "additional_subdomains": [],
                    "expired_certs": []
                },
                "success_metrics": {
                    "certificates_analyzed": ">= 90%",
                    "subdomain_discovery": "any additional findings"
                }
            }
        ])
    
    # PORT SCANNING SCENARIOS (15 scenarios)
    scan_configs = [
        ("quick", "Top 1000 ports", "-F"),
        ("standard", "All TCP ports", "-p-"),
        ("service", "Service detection", "-sV"),
        ("os", "OS fingerprinting", "-O"),
        ("script", "Default scripts", "-sC"),
    ]
    
    for i, (scan_type, desc, nmap_flag) in enumerate(scan_configs, 1):
        scenarios.extend([
            {
                "scenario_id": f"L1_S{i:02d}A",
                "task": f"Nmap {scan_type} scan",
                "difficulty": "easy",
                "input": f"Perform {desc} on 192.168.1.100",
                "steps": [
                    f"Run nmap {nmap_flag} 192.168.1.100",
                    "Parse nmap XML output",
                    "Identify open ports",
                    "Extract service versions",
                    "Generate port scan report"
                ],
                "expected_duration": "3-10 minutes",
                "expected_output": {
                    "open_ports": [],
                    "services": {},
                    "os_guess": "str or None"
                },
                "success_metrics": {
                    "ports_detected": ">= 80%",
                    "service_accuracy": ">= 70%",
                    "false_positives": "< 5%"
                }
            },
            {
                "scenario_id": f"L1_S{i:02d}B",
                "task": f"Masscan {scan_type} sweep",
                "difficulty": "easy",
                "input": f"Fast port sweep of 192.168.1.0/24",
                "steps": [
                    "Run masscan 192.168.1.0/24 -p1-1000 --rate=1000",
                    "Parse masscan output",
                    "Identify live hosts",
                    "Count open ports per host",
                    "Generate network map"
                ],
                "expected_duration": "1-3 minutes",
                "expected_output": {
                    "live_hosts": [],
                    "total_open_ports": "int",
                    "most_common_ports": []
                },
                "success_metrics": {
                    "speed": "< 5 minutes for /24",
                    "accuracy": ">= 85%"
                }
            },
            {
                "scenario_id": f"L1_S{i:02d}C",
                "task": f"Combined reconnaissance and scan",
                "difficulty": "medium",
                "input": f"Full discovery of example.com infrastructure",
                "steps": [
                    "Enumerate subdomains",
                    "Resolve to IP addresses",
                    "Perform port scan on all IPs",
                    "Identify services",
                    "Generate comprehensive report"
                ],
                "expected_duration": "10-15 minutes",
                "expected_output": {
                    "subdomains": [],
                    "ip_addresses": [],
                    "open_ports": {},
                    "services": {}
                },
                "success_metrics": {
                    "completeness": ">= 85%",
                    "correlation_accuracy": ">= 90%"
                }
            }
        ])
    
    # VULNERABILITY SCANNING SCENARIOS (10 scenarios)
    vuln_types = [
        ("web", "nikto", "Web server vulnerabilities"),
        ("ssl", "testssl.sh", "SSL/TLS configuration"),
        ("cve", "nuclei", "Known CVE detection"),
        ("headers", "curl", "Security headers check"),
        ("misc", "nuclei", "Misconfiguration detection"),
    ]
    
    for i, (type_name, tool, desc) in enumerate(vuln_types, 1):
        scenarios.extend([
            {
                "scenario_id": f"L1_V{i:02d}A",
                "task": f"{desc} scan",
                "difficulty": "easy",
                "input": f"Scan https://example.com for {desc.lower()}",
                "steps": [
                    f"Run {tool} on target",
                    "Parse tool output",
                    "Filter by severity (critical/high/medium)",
                    "Remove false positives",
                    "Generate vulnerability report"
                ],
                "expected_duration": "5-8 minutes",
                "expected_output": {
                    "vulnerabilities": [],
                    "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                    "false_positives_removed": 0
                },
                "success_metrics": {
                    "detection_rate": ">= 85%",
                    "false_positive_rate": "< 10%"
                }
            },
            {
                "scenario_id": f"L1_V{i:02d}B",
                "task": f"Automated {desc} validation",
                "difficulty": "medium",
                "input": f"Validate scan results from {tool}",
                "steps": [
                    "Parse scan results",
                    "Cross-reference with CVE database",
                    "Check exploit availability",
                    "Calculate CVSS scores",
                    "Prioritize findings"
                ],
                "expected_duration": "3-5 minutes",
                "expected_output": {
                    "validated_vulns": [],
                    "cve_mappings": {},
                    "prioritized_list": []
                },
                "success_metrics": {
                    "validation_accuracy": ">= 90%",
                    "prioritization_quality": ">= 85%"
                }
            }
        ])
    
    # REPORTING SCENARIOS (10 scenarios)
    report_types = [
        ("executive", "Executive summary for C-level"),
        ("technical", "Technical details for security team"),
        ("compliance", "Compliance-focused (PCI-DSS, SOC2)"),
        ("remediation", "Remediation roadmap with code examples"),
        ("trend", "Trend analysis across multiple scans"),
    ]
    
    for i, (report_type, desc) in enumerate(report_types, 1):
        scenarios.extend([
            {
                "scenario_id": f"L1_REP{i:02d}A",
                "task": f"Generate {desc}",
                "difficulty": "easy",
                "input": f"Create {report_type} report from scan data",
                "steps": [
                    "Load scan results (JSON/XML)",
                    "Aggregate findings by severity",
                    "Calculate metrics (CVSS, risk score)",
                    f"Format as {report_type} report",
                    "Export to PDF/HTML"
                ],
                "expected_duration": "3-5 minutes",
                "expected_output": {
                    "report_format": report_type,
                    "sections": [],
                    "finding_count": "int",
                    "export_format": ["pdf", "html"]
                },
                "success_metrics": {
                    "completeness": ">= 95%",
                    "readability": "high",
                    "accuracy": ">= 98%"
                }
            },
            {
                "scenario_id": f"L1_REP{i:02d}B",
                "task": f"Automated {report_type} generation with AI",
                "difficulty": "medium",
                "input": f"Use AI to enhance {report_type} report",
                "steps": [
                    "Parse technical findings",
                    "Use GPT to generate executive summary",
                    "Create business impact analysis",
                    "Add remediation recommendations",
                    "Format and export"
                ],
                "expected_duration": "4-6 minutes",
                "expected_output": {
                    "ai_generated_summary": "str",
                    "business_impact": "str",
                    "recommendations": []
                },
                "success_metrics": {
                    "ai_quality": ">= 90%",
                    "business_relevance": ">= 85%"
                }
            }
        ])
    
    return scenarios[:50]  # Return exactly 50 scenarios


def generate_level2_scenarios():
    """Generate 100 Level 2 (Medium) training scenarios"""
    scenarios = []
    
    # VULNERABILITY VALIDATION SCENARIOS (30 scenarios)
    vuln_categories = [
        ("sql_injection", "SQL Injection", ["sqlmap", "manual payloads"]),
        ("xss", "Cross-Site Scripting", ["xsstrike", "manual payloads"]),
        ("csrf", "CSRF", ["burp", "manual testing"]),
        ("idor", "IDOR", ["burp", "manual ID manipulation"]),
        ("auth_bypass", "Authentication Bypass", ["hydra", "manual testing"]),
        ("file_upload", "File Upload", ["manual testing", "burp"]),
    ]
    
    for i, (vuln_type, name, tools) in enumerate(vuln_categories, 1):
        for j in range(5):  # 5 scenarios per vulnerability type
            scenarios.append({
                "scenario_id": f"L2_VAL{i:02d}_{j+1}",
                "task": f"Validate {name} vulnerability",
                "difficulty": "medium",
                "input": f"Confirm potential {name} at /endpoint?param=value",
                "steps": [
                    f"Test with {tools[0]}",
                    "Verify with manual payloads",
                    "Check exploit availability",
                    "Map to CVE if applicable",
                    "Calculate risk score",
                    "Document validation"
                ],
                "expected_duration": "10-15 minutes",
                "expected_output": {
                    "validated": "bool",
                    "confidence": "0.0-1.0",
                    "exploit_available": "bool",
                    "cvss_score": "float",
                    "cve_id": "str or None"
                },
                "success_metrics": {
                    "validation_accuracy": ">= 95%",
                    "false_positive_rate": "< 5%",
                    "confidence_calibration": ">= 90%"
                }
            })
    
    # BASIC EXPLOITATION SCENARIOS (30 scenarios)
    exploit_types = [
        ("sqli_read", "SQL Injection (Read-only)", "Database enumeration"),
        ("xss_reflected", "Reflected XSS PoC", "Cookie theft demo"),
        ("default_creds", "Default Credentials", "Admin access"),
        ("path_traversal", "Path Traversal", "File disclosure"),
        ("xxe", "XXE", "XML external entity"),
        ("ssrf", "SSRF", "Internal service access"),
    ]
    
    for i, (exploit_type, name, impact) in enumerate(exploit_types, 1):
        for j in range(5):  # 5 scenarios per exploit type
            scenarios.append({
                "scenario_id": f"L2_EXP{i:02d}_{j+1}",
                "task": f"Exploit {name}",
                "difficulty": "medium",
                "input": f"Demonstrate {impact} via {name}",
                "steps": [
                    "Confirm vulnerability exists",
                    "Select appropriate tool/technique",
                    "Execute safe PoC",
                    "Demonstrate impact (read-only)",
                    "Document exploitation steps",
                    "Provide remediation code"
                ],
                "expected_duration": "15-20 minutes",
                "expected_output": {
                    "exploitation_successful": "bool",
                    "impact_demonstrated": "str",
                    "screenshots": [],
                    "remediation_code": "str"
                },
                "success_metrics": {
                    "exploitation_success_rate": ">= 80%",
                    "safety_compliance": "100%",
                    "documentation_quality": ">= 90%"
                }
            })
    
    # INTELLIGENT PRIORITIZATION SCENARIOS (20 scenarios)
    for i in range(1, 21):
        scenarios.append({
            "scenario_id": f"L2_PRI{i:02d}",
            "task": f"Prioritize vulnerability set #{i}",
            "difficulty": "medium",
            "input": f"Rank 10 vulnerabilities for remediation",
            "steps": [
                "Load vulnerability dataset",
                "Calculate CVSS base scores",
                "Check exploit availability",
                "Assess asset criticality",
                "Estimate business impact",
                "Calculate composite risk scores",
                "Rank vulnerabilities",
                "Generate remediation roadmap"
            ],
            "expected_duration": "8-12 minutes",
            "expected_output": {
                "ranked_vulnerabilities": [],
                "risk_scores": {},
                "remediation_timeline": {},
                "business_justification": "str"
            },
            "success_metrics": {
                "ranking_accuracy": ">= 85%",
                "matches_expert_opinion": ">= 80%",
                "business_context_present": "bool"
            }
        })
    
    # ADVANCED REPORTING SCENARIOS (20 scenarios)
    for i in range(1, 21):
        scenarios.append({
            "scenario_id": f"L2_REP{i:02d}",
            "task": f"Advanced report generation #{i}",
            "difficulty": "medium",
            "input": f"Create comprehensive security assessment report",
            "steps": [
                "Aggregate findings from all tools",
                "Generate AI-powered executive summary",
                "Create technical deep-dive sections",
                "Add compliance mapping (OWASP, PCI-DSS)",
                "Include remediation code snippets",
                "Generate attack path visualization",
                "Export multi-format (PDF, HTML, JSON)"
            ],
            "expected_duration": "10-15 minutes",
            "expected_output": {
                "executive_summary": "str (AI-generated)",
                "technical_details": [],
                "compliance_gaps": {},
                "remediation_code": {},
                "visualizations": [],
                "export_formats": ["pdf", "html", "json"]
            },
            "success_metrics": {
                "report_completeness": ">= 95%",
                "executive_summary_quality": ">= 90%",
                "code_snippet_accuracy": ">= 95%"
            }
        })
    
    return scenarios[:100]  # Return exactly 100 scenarios


def generate_level3_scenarios():
    """Generate 200 Level 3 (Expert) training scenarios"""
    scenarios = []
    
    # ADVANCED EXPLOITATION & ATTACK CHAINS (80 scenarios)
    attack_chains = [
        ("web_to_server", "SQL Injection → RCE → Lateral Movement"),
        ("auth_to_admin", "Auth Bypass → Privilege Escalation → Admin"),
        ("xss_to_takeover", "XSS → Session Hijack → Account Takeover"),
        ("upload_to_shell", "File Upload → Web Shell → Post-Exploitation"),
        ("ssrf_to_cloud", "SSRF → AWS Metadata → Cloud Compromise"),
    ]
    
    for i, (chain_type, description) in enumerate(attack_chains, 1):
        for j in range(16):  # 16 scenarios per attack chain type
            scenarios.append({
                "scenario_id": f"L3_CHAIN{i:02d}_{j+1:02d}",
                "task": f"Execute attack chain: {description}",
                "difficulty": "expert",
                "input": f"Demonstrate full impact from external to internal compromise",
                "steps": [
                    "Identify initial attack vector",
                    "Gain initial foothold",
                    "Enumerate internal network",
                    "Identify privilege escalation path",
                    "Demonstrate lateral movement",
                    "Access target data/system",
                    "Document complete attack chain",
                    "Calculate time-to-compromise",
                    "Provide defense-in-depth recommendations"
                ],
                "expected_duration": "45-60 minutes",
                "expected_output": {
                    "attack_chain_steps": [],
                    "time_to_compromise": "int (minutes)",
                    "impact_demonstrated": "str",
                    "business_impact_cost": "float",
                    "remediation_roadmap": []
                },
                "success_metrics": {
                    "chain_completeness": "100%",
                    "exploitation_success": ">= 90%",
                    "documentation_quality": ">= 95%",
                    "remediation_comprehensiveness": ">= 90%"
                }
            })
    
    # BUSINESS LOGIC TESTING (40 scenarios)
    logic_flaws = [
        ("race_condition", "Payment processing race conditions"),
        ("idor_advanced", "Multi-step IDOR chains"),
        ("workflow_bypass", "Checkout/approval workflow bypass"),
        ("price_manipulation", "E-commerce price manipulation"),
        ("coupon_stacking", "Discount/coupon abuse"),
        ("state_manipulation", "Application state tampering"),
        ("toctou", "Time-of-check vs time-of-use"),
        ("auth_flow_bypass", "Multi-factor auth bypass"),
    ]
    
    for i, (flaw_type, description) in enumerate(logic_flaws, 1):
        for j in range(5):  # 5 scenarios per flaw type
            scenarios.append({
                "scenario_id": f"L3_LOGIC{i:02d}_{j+1}",
                "task": f"Identify {description}",
                "difficulty": "expert",
                "input": f"Test application for {description}",
                "steps": [
                    "Map application workflow",
                    "Identify trust boundaries",
                    "Test boundary conditions",
                    "Attempt workflow bypass",
                    "Test concurrent requests",
                    "Manipulate state transitions",
                    "Demonstrate financial/security impact",
                    "Document business logic flaw",
                    "Provide secure design recommendations"
                ],
                "expected_duration": "30-40 minutes",
                "expected_output": {
                    "flaw_identified": "bool",
                    "financial_impact": "float",
                    "reproduction_steps": [],
                    "poc_code": "str",
                    "secure_design": "str"
                },
                "success_metrics": {
                    "detection_rate": ">= 70%",
                    "impact_calculation_accuracy": ">= 85%",
                    "remediation_quality": ">= 90%"
                }
            })
    
    # ATTACK PATH ANALYSIS (30 scenarios)
    for i in range(1, 31):
        scenarios.append({
            "scenario_id": f"L3_GRAPH{i:02d}",
            "task": f"Attack graph analysis #{i}",
            "difficulty": "expert",
            "input": f"Generate optimal attack path from external to database",
            "steps": [
                "Enumerate all assets and vulnerabilities",
                "Construct attack graph (nodes=assets, edges=vulns)",
                "Calculate multiple attack paths",
                "Use Dijkstra's algorithm for shortest path",
                "Estimate time-to-compromise per path",
                "Identify critical vulnerabilities",
                "Calculate defense priority",
                "Generate visual attack graph"
            ],
            "expected_duration": "20-30 minutes",
            "expected_output": {
                "attack_graph": "graph data structure",
                "optimal_path": [],
                "alternative_paths": [],
                "critical_vulnerabilities": [],
                "time_estimates": {},
                "visualization": "graph image"
            },
            "success_metrics": {
                "path_optimality": ">= 90%",
                "critical_vuln_accuracy": ">= 95%",
                "visualization_quality": "high"
            }
        })
    
    # AUTONOMOUS DECISION MAKING (25 scenarios)
    for i in range(1, 26):
        scenarios.append({
            "scenario_id": f"L3_AUTO{i:02d}",
            "task": f"Autonomous penetration test #{i}",
            "difficulty": "expert",
            "input": f"Conduct full penetration test with minimal human intervention",
            "steps": [
                "Analyze target and determine scope",
                "Select optimal tools and techniques",
                "Execute reconnaissance autonomously",
                "Identify and validate vulnerabilities",
                "Develop exploitation strategy",
                "Execute attack chain",
                "Adapt based on defensive responses",
                "Document findings in real-time",
                "Generate comprehensive report",
                "Present findings to stakeholder"
            ],
            "expected_duration": "90-120 minutes",
            "expected_output": {
                "autonomous_decisions": [],
                "tools_selected": [],
                "vulnerabilities_found": [],
                "exploitation_results": [],
                "adaptation_events": [],
                "final_report": "comprehensive report object"
            },
            "success_metrics": {
                "autonomy_level": ">= 85%",
                "decision_quality": ">= 90%",
                "success_rate": ">= 95%",
                "human_intervention_minimal": "< 15%"
            }
        })
    
    # DEFENSE EVASION (25 scenarios)
    for i in range(1, 26):
        scenarios.append({
            "scenario_id": f"L3_EVASION{i:02d}",
            "task": f"WAF/IDS evasion #{i}",
            "difficulty": "expert",
            "input": f"Bypass WAF and IDS while exploiting vulnerabilities",
            "steps": [
                "Detect defensive measures (WAF, IDS, rate limiting)",
                "Identify blocking patterns",
                "Develop evasion techniques",
                "Test with obfuscated payloads",
                "Use encoding/encryption",
                "Implement timing delays",
                "Adapt based on blocks",
                "Successfully bypass defenses",
                "Document evasion methodology"
            ],
            "expected_duration": "40-50 minutes",
            "expected_output": {
                "defensive_measures_detected": [],
                "evasion_techniques_used": [],
                "bypass_successful": "bool",
                "adaptation_cycles": "int",
                "methodology_doc": "str"
            },
            "success_metrics": {
                "waf_bypass_rate": ">= 80%",
                "ids_evasion_rate": ">= 85%",
                "adaptation_efficiency": ">= 90%"
            }
        })
    
    return scenarios[:200]  # Return exactly 200 scenarios


# Generate all scenarios
LEVEL_1_EXPANDED_SCENARIOS = generate_level1_scenarios()
LEVEL_2_EXPANDED_SCENARIOS = generate_level2_scenarios()
LEVEL_3_EXPANDED_SCENARIOS = generate_level3_scenarios()
