from .level2_config import LEVEL_2_CAPABILITIES

LEVEL_3_CAPABILITIES = {
    **LEVEL_2_CAPABILITIES,  # Inherit from Levels 1-2
    
    "advanced_exploitation": {
        "automation_level": 75,
        "capabilities": [
            "multi_stage_attack_chains",
            "custom_exploit_generation",
            "privilege_escalation",
            "lateral_movement_demo",
            "post_exploitation_enumeration",
            "persistence_identification"
        ],
        "frameworks": ["metasploit", "empire", "cobalt_strike_simulation"],
        "requires_approval": "initial_only",  # Autonomous after first approval
        "learning_enabled": True  # Learns from successes/failures
    },
    
    "business_logic_testing": {
        "automation_level": 60,
        "test_categories": [
            "workflow_bypass",
            "race_conditions",
            "idor_testing",
            "price_manipulation",
            "authentication_bypass",
            "authorization_flaws"
        ],
        "test_generation": "automated",  # AI generates custom tests
        "manual_review_required": "complex_workflows"
    },
    
    "attack_path_analysis": {
        "automation_level": 85,
        "algorithms": ["dijkstra", "a_star", "breadth_first"],
        "features": [
            "graph_construction",
            "optimal_path_calculation",
            "time_to_compromise_estimation",
            "critical_vulnerability_identification",
            "defense_evasion_planning"
        ]
    },
    
    "autonomous_decision_making": {
        "automation_level": 80,
        "capabilities": [
            "dynamic_tool_selection",
            "adaptive_strategy",
            "real_time_threat_intel_integration",
            "self_correction",
            "continuous_learning"
        ],
        "human_intervention": [
            "destructive_operations",
            "out_of_scope_actions",
            "legal_gray_areas",
            "final_report_approval"
        ]
    },
    
    "advanced_reporting": {
        "automation_level": 90,
        "formats": [
            "executive_presentation (PPTX)",
            "technical_report (PDF, 50+ pages)",
            "video_poc (MP4)",
            "interactive_dashboard",
            "api_integration (JSON/SARIF)"
        ],
        "features": [
            "trend_analysis",
            "security_posture_scoring",
            "benchmark_comparison",
            "roi_calculation",
            "automated_qa"  # Report answers questions
        ]
    }
}

LEVEL_3_TRAINING_SCENARIOS = [
    {
        "scenario_id": "L3_001",
        "task": "Full attack chain demonstration",
        "difficulty": "expert",
        "input": "Compromise internal database from external position",
        "steps": [
            "Identify external attack surface",
            "Find SQL injection vulnerability",
            "Extract database credentials from config files",
            "Establish database connection",
            "Enumerate database structure",
            "Identify sensitive data tables",
            "Demonstrate data access (1 record)",
            "Identify lateral movement opportunities",
            "Demonstrate privilege escalation path",
            "Document complete attack chain",
            "Calculate time-to-compromise",
            "Provide defense-in-depth recommendations"
        ],
        "expected_duration": "45-60 minutes",
        "success_metrics": {
            "attack_chain_completeness": "100%",
            "exploitation_success": ">= 90%",
            "documentation_quality": ">= 95%",
            "business_impact_analysis": "present",
            "defense_recommendations": "comprehensive"
        }
    },
    {
        "scenario_id": "L3_002",
        "task": "Business logic flaw identification",
        "difficulty": "expert",
        "input": "E-commerce application with checkout flow",
        "steps": [
            "Map complete checkout workflow",
            "Identify trust boundaries",
            "Test negative quantity exploit",
            "Test race conditions in payment",
            "Test coupon stacking vulnerabilities",
            "Test IDOR in order management",
            "Test price manipulation via API",
            "Document financial impact",
            "Provide secure design recommendations"
        ],
        "expected_duration": "30-40 minutes",
        "success_metrics": {
            "logic_flaws_found": ">= 5",
            "financial_impact_calculated": "yes",
            "poc_provided": "yes"
        }
    },
    {
        "scenario_id": "L3_003",
        "task": "Adaptive exploitation with defense evasion",
        "difficulty": "expert",
        "input": "Target protected by WAF and IDS",
        "steps": [
            "Detect WAF/IDS presence",
            "Identify blocking patterns",
            "Develop evasion techniques",
            "Test with obfuscated payloads",
            "Adapt based on defensive responses",
            "Successfully bypass protections",
            "Document evasion methodology"
        ],
        "expected_duration": "40-50 minutes",
        "success_metrics": {
            "waf_bypass": "successful",
            "ids_evasion": "successful",
            "adaptation_cycles": "<= 3"
        }
    }
]

LEVEL_3_PROMPTS = {
    "advanced_exploitation": """
You are an elite penetration testing AI with autonomous exploitation capabilities.

ADVANCED CAPABILITIES:
- Chain vulnerabilities for maximum impact
- Develop custom exploits on-the-fly
- Bypass security controls (WAF, IDS, IPS)
- Perform privilege escalation
- Conduct lateral movement
- Establish persistence (read-only demonstration)
- Adapt strategies based on defensive responses

AUTONOMOUS EXPLOITATION WORKFLOW:
1. Analyze target infrastructure
2. Identify multiple attack vectors
3. Calculate optimal attack path (graph analysis)
4. Execute multi-stage exploitation
5. Adapt if defenses activate
6. Demonstrate full impact
7. Clean up and document
8. Provide comprehensive remediation
""",
    "business_logic": """
You are specialized in identifying business logic flaws that automated scanners miss.

BUSINESS LOGIC TESTING AREAS:
1. Workflow bypass (skip payment steps, admin approval)
2. Race conditions (concurrent transactions)
3. IDOR (access other users' data by changing IDs)
4. Price manipulation (negative quantities, discount stacking)
5. Authentication flow bypass (password reset, 2FA bypass)
6. Authorization flaws (privilege escalation, role confusion)
7. Time-of-check vs time-of-use (TOCTOU)
8. State management flaws

TESTING METHODOLOGY:
1. Map application workflows
2. Identify trust boundaries
3. Test boundary conditions
4. Attempt workflow bypasses
5. Test with concurrent requests
6. Manipulate state transitions
7. Test for IDOR in all resource endpoints
8. Validate all authorization checks
""",
    "attack_path": """
You are an AI that plans optimal attack strategies using graph theory.

ATTACK GRAPH CONSTRUCTION:
1. Nodes: Assets (servers, databases, users, credentials)
2. Edges: Vulnerabilities connecting assets
3. Weights: Exploitability + Impact
4. Goal: Find shortest path from external → target (e.g., database)

GRAPH ANALYSIS:
- Use Dijkstra's algorithm for shortest path
- Calculate multiple paths for redundancy
- Estimate time-to-compromise for each path
- Identify critical vulnerabilities (if fixed, blocks all paths)
"""
}
