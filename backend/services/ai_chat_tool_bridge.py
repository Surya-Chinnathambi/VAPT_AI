"""
AI Chat to Real-Time Security Scanning Bridge
Connects AI chat messages to Docker-based security tools execution
Integrated with Kali Linux for comprehensive VAPT
"""
import asyncio
import json
import logging
import re
from typing import Dict, List, Any, Optional
from datetime import datetime

from core.realtime_tool_executor import RealtimeToolExecutor
from core.enhanced_docker_manager import get_enhanced_docker_manager
from services.ai_chat_service import get_chat_service
from services.kali_tools_executor import get_kali_executor
from core.ai_security_prompts import get_system_prompt
from mcp_server.tools import VaptMcpTools

logger = logging.getLogger(__name__)


class AIChatToolBridge:
    """
    Bridges AI chat to real-time security tool execution
    Parses user intent and triggers appropriate Docker tools
    """
    
    def __init__(self):
        self.tool_executor = RealtimeToolExecutor()
        self.docker_manager = get_enhanced_docker_manager()
        self.chat_service = get_chat_service()
        self.kali_executor = get_kali_executor()  # Kali Linux tools
        self.mcp_tools = VaptMcpTools() # Initialize MCP Tools
        
        # Expanded tool keywords with Kali tools
        self.tool_keywords = {
            # Network Scanning
            'nmap': ['scan', 'port', 'nmap', 'network', 'service detection', 'host discovery'],
            'masscan': ['masscan', 'fast scan', 'port sweep'],
            
            # Web Scanning
            'nikto': ['nikto', 'web scan', 'web vulnerabilities', 'http'],
            'nuclei': ['nuclei', 'template', 'multiple vulnerabilities', 'cve scan'],
            'sqlmap': ['sql injection', 'sqlmap', 'database', 'sql'],
            'wpscan': ['wordpress', 'wp', 'wpscan', 'cms'],
            'dirb': ['dirb', 'directory', 'bruteforce'],
            'gobuster': ['gobuster', 'directory scan', 'brute force', 'files'],
            'ffuf': ['ffuf', 'fuzzing', 'web fuzzer'],
            'wfuzz': ['wfuzz', 'parameter fuzzing'],
            'commix': ['commix', 'command injection'],
            'zaproxy': ['zap', 'web app', 'proxy', 'spider', 'owasp zap'],
            'wafw00f': ['waf', 'firewall detection', 'wafw00f'],
            
            # SSL/TLS
            'testssl': ['ssl', 'tls', 'certificate', 'https', 'testssl'],
            'sslyze': ['sslyze', 'ssl configuration'],
            'sslscan': ['sslscan', 'ssl cipher'],
            
            # Reconnaissance
            'subfinder': ['subdomain', 'subfinder', 'dns enumeration'],
            'amass': ['amass', 'recon', 'asset discovery', 'osint'],
            'sublist3r': ['sublist3r', 'subdomain enumeration'],
            'theharvester': ['harvester', 'email', 'osint', 'domain info'],
            'dnsenum': ['dnsenum', 'dns records'],
            'whatweb': ['whatweb', 'technology', 'fingerprint'],
            
            # Exploitation
            'metasploit': ['metasploit', 'msfconsole', 'exploit', 'framework'],
            'searchsploit': ['searchsploit', 'exploitdb', 'exploit search'],
            
            # Password Cracking
            'hydra': ['hydra', 'password crack', 'brute force login'],
            'john': ['john', 'john the ripper', 'hash crack'],
            
            # Other
            'trivy': ['trivy', 'container', 'docker scan', 'image'],
            'git-secrets': ['git secrets', 'credentials', 'api keys']
        }
        
        # Scan type keywords
        self.scan_type_keywords = {
            'quick': ['quick', 'fast', 'basic', 'simple'],
            'standard': ['standard', 'normal', 'default'],
            'full': ['full', 'complete', 'comprehensive', 'thorough'],
            'aggressive': ['aggressive', 'deep', 'intensive']
        }
    
    async def process_chat_message(
        self,
        user_message: str,
        session_id: str,
        progress_callback: Optional[callable] = None
    ) -> Dict[str, Any]:
        """
        Process chat message and execute security tools if needed
        
        Args:
            user_message: User's chat message
            session_id: Chat session ID
            progress_callback: WebSocket callback for real-time updates
        
        Returns:
            {
                "ai_response": "...",
                "tools_executed": ["nmap", "nikto"],
                "scan_results": {...},
                "execution_summary": "..."
            }
        """
        logger.info(f"Processing chat message: {user_message[:100]}...")
        
        # Step 1: Parse user intent with AI
        intent_analysis = await self._analyze_user_intent(user_message)
        
        # Step 2: Extract target and parameters
        target = self._extract_target(user_message)
        scan_type = self._extract_scan_type(user_message)
        
        # Step 3: Determine which tools to run
        tools_to_execute = self._determine_tools(user_message, intent_analysis)
        
        # Step 4: Execute tools if target detected
        scan_results = {}
        if target and tools_to_execute:
            logger.info(f"Target: {target}, Tools: {tools_to_execute}, Type: {scan_type}")
            
            # Notify user that scan is starting
            if progress_callback:
                await progress_callback({
                    "type": "scan_initiated",
                    "target": target,
                    "tools": tools_to_execute,
                    "scan_type": scan_type
                })
            
            # TRY MCP EXECUTION FIRST (N2N Architecture)
            mcp_executed = False
            try:
                if "nmap" in tools_to_execute or "scan" in tools_to_execute:
                    logger.info("Delegating to MCP Server for N2N execution...")
                    # Use MCP Tool
                    mcp_result = await self.mcp_tools.handle_call_tool(
                        "run_vapt_scan", 
                        {"target": target, "scan_type": scan_type}
                    )
                    
                    scan_results["mcp_vapt"] = {
                        "status": "initiated",
                        "details": mcp_result.content[0]['text'] if mcp_result.content else "Scan started via MCP"
                    }
                    mcp_executed = True
            except Exception as mcp_error:
                logger.error(f"MCP Execution failed: {mcp_error}")

            # Fallback to Docker execution if MCP didn't handle it or failed
            if not mcp_executed and self.tool_executor.docker_available:
                try:
                    scan_results = await self._execute_tools_parallel(
                        target=target,
                        tools=tools_to_execute,
                        scan_type=scan_type,
                        progress_callback=progress_callback
                    )
                except Exception as e:
                    logger.error(f"Tool execution failed: {e}")
                    scan_results = {
                        "error": "Docker not accessible from backend container. Tools cannot execute.",
                        "message": "To enable scanning, configure Docker socket access or use external scanning service."
                    }
            elif not mcp_executed:
                logger.warning("Docker not available - skipping tool execution")
                scan_results.update({
                    "error": "Docker not available",
                    "message": "Security scanning tools require Docker access. Please configure Docker socket mounting."
                })
        
        # Step 5: Generate AI response with scan results
        ai_response = await self._generate_response_with_results(
            user_message=user_message,
            intent=intent_analysis,
            target=target,
            scan_results=scan_results
        )
        
        # Step 6: Create execution summary
        execution_summary = self._create_execution_summary(
            tools_executed=list(scan_results.keys()),
            target=target,
            results=scan_results
        )
        
        return {
            "ai_response": ai_response,
            "tools_executed": list(scan_results.keys()),
            "scan_results": scan_results,
            "execution_summary": execution_summary,
            "target": target,
            "intent": intent_analysis
        }
    
    async def _analyze_user_intent(self, message: str) -> Dict[str, Any]:
        """Use AI to analyze user intent"""
        try:
            intent_prompt = f"""Analyze this security request and determine:
1. Primary intent (scan/analyze/consult/remediate)
2. Security tools needed (nmap/nikto/nuclei/sqlmap/etc.)
3. Urgency level (low/medium/high/critical)
4. Scope (quick/standard/full/aggressive)

User message: "{message}"

Respond in JSON format:
{{
    "intent": "scan|analyze|consult|remediate",
    "tools_suggested": ["tool1", "tool2"],
    "urgency": "low|medium|high|critical",
    "scope": "quick|standard|full|aggressive",
    "requires_execution": true|false
}}"""
            
            response = await self.chat_service.chat(
                message=intent_prompt,
                history=None,
                context=None
            )
            
            # Parse JSON response
            try:
                intent_data = json.loads(response.get('response', '{}'))
                return intent_data
            except json.JSONDecodeError:
                # Fallback to keyword-based analysis
                return self._keyword_based_intent(message)
        
        except Exception as e:
            logger.error(f"Intent analysis failed: {e}")
            return self._keyword_based_intent(message)
    
    def _keyword_based_intent(self, message: str) -> Dict[str, Any]:
        """Fallback keyword-based intent detection"""
        message_lower = message.lower()
        
        # Detect tools
        tools_detected = []
        for tool, keywords in self.tool_keywords.items():
            if any(keyword in message_lower for keyword in keywords):
                tools_detected.append(tool)
        
        # Detect scan type
        scan_type = "standard"
        for stype, keywords in self.scan_type_keywords.items():
            if any(keyword in message_lower for keyword in keywords):
                scan_type = stype
                break
        
        # Detect urgency
        urgency = "medium"
        if any(word in message_lower for word in ['critical', 'urgent', 'immediately', 'asap']):
            urgency = "critical"
        elif any(word in message_lower for word in ['high priority', 'important']):
            urgency = "high"
        
        # Determine intent
        intent = "consult"
        if any(word in message_lower for word in ['scan', 'check', 'test', 'analyze', 'assess']):
            intent = "scan"
        elif any(word in message_lower for word in ['fix', 'remediate', 'patch', 'secure']):
            intent = "remediate"
        
        return {
            "intent": intent,
            "tools_suggested": tools_detected,
            "urgency": urgency,
            "scope": scan_type,
            "requires_execution": len(tools_detected) > 0 and intent == "scan"
        }
    
    def _extract_target(self, message: str) -> Optional[str]:
        """Extract target URL/IP/domain from message"""
        # URL pattern
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        url_match = re.search(url_pattern, message)
        if url_match:
            return url_match.group(0)
        
        # Domain pattern
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        domain_match = re.search(domain_pattern, message.lower())
        if domain_match:
            domain = domain_match.group(0)
            # Filter out common false positives
            if domain not in ['example.com', 'test.com', 'localhost.com']:
                return domain
        
        # IP address pattern
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_match = re.search(ip_pattern, message)
        if ip_match:
            return ip_match.group(0)
        
        return None
    
    def _extract_scan_type(self, message: str) -> str:
        """Extract scan type from message"""
        message_lower = message.lower()
        
        for scan_type, keywords in self.scan_type_keywords.items():
            if any(keyword in message_lower for keyword in keywords):
                return scan_type
        
        return "standard"
    
    def _determine_tools(
        self,
        message: str,
        intent_analysis: Dict[str, Any]
    ) -> List[str]:
        """Determine which tools to execute"""
        # If AI suggested tools, use those
        if intent_analysis.get('tools_suggested'):
            return intent_analysis['tools_suggested']
        
        # Otherwise use keyword detection
        message_lower = message.lower()
        tools = []
        
        for tool, keywords in self.tool_keywords.items():
            if any(keyword in message_lower for keyword in keywords):
                tools.append(tool)
        
        # Default tools for generic scan requests
        if not tools and any(word in message_lower for word in ['scan', 'check', 'test']):
            tools = ['nmap', 'nikto']  # Default security scan
        
        return tools
    
    async def _execute_tools_parallel(
        self,
        target: str,
        tools: List[str],
        scan_type: str,
        progress_callback: Optional[callable] = None
    ) -> Dict[str, Any]:
        """Execute multiple tools in parallel using Kali Linux container"""
        logger.info(f"Executing {len(tools)} Kali tools on {target}")
        
        # Map tools to Kali executor methods
        kali_tools_map = {
            'nmap': lambda: self.kali_executor.nmap_scan(target, scan_type),
            'masscan': lambda: self.kali_executor.masscan_scan(target),
            'nikto': lambda: self.kali_executor.nikto_scan(target),
            'nuclei': lambda: self.kali_executor.nuclei_scan(target),
            'sqlmap': lambda: self.kali_executor.sqlmap_scan(target),
            'wpscan': lambda: self.kali_executor.wpscan_scan(target),
            'testssl': lambda: self.kali_executor.testssl_scan(target),
            'gobuster': lambda: self.kali_executor.gobuster_scan(target),
            'dirb': lambda: self.kali_executor.dirb_scan(target),
            'ffuf': lambda: self.kali_executor.ffuf_scan(target),
            'wfuzz': lambda: self.kali_executor.wfuzz_scan(target),
            'commix': lambda: self.kali_executor.commix_scan(target),
            'zaproxy': lambda: self.kali_executor.zaproxy_scan(target),
            'wafw00f': lambda: self.kali_executor.wafw00f_scan(target),
            'sslyze': lambda: self.kali_executor.sslyze_scan(target),
            'sslscan': lambda: self.kali_executor.sslscan_scan(target),
            'subfinder': lambda: self.kali_executor.subfinder_scan(target),
            'amass': lambda: self.kali_executor.amass_enum(target),
            'dnsenum': lambda: self.kali_executor.dnsenum_scan(target),
            'whatweb': lambda: self.kali_executor.whatweb_scan(target),
            'theharvester': lambda: self.kali_executor.theharvester_scan(target),
        }
        
        tasks = []
        for tool in tools:
            if tool in kali_tools_map:
                # Use Kali Linux container
                tasks.append(kali_tools_map[tool]())
            else:
                # Fallback to original executor
                task = self.tool_executor.execute_tool_realtime(
                    tool_name=tool,
                    target=target,
                    scan_type=scan_type,
                    progress_callback=progress_callback
                )
                tasks.append(task)
        
        # Execute all tools concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Build results dictionary
        scan_results = {}
        for idx, tool in enumerate(tools):
            result = results[idx]
            if isinstance(result, Exception):
                scan_results[tool] = {
                    "success": False,
                    "error": str(result),
                    "tool": tool
                }
            else:
                scan_results[tool] = result
        
        return scan_results
    
    async def _generate_response_with_results(
        self,
        user_message: str,
        intent: Dict[str, Any],
        target: Optional[str],
        scan_results: Dict[str, Any]
    ) -> str:
        """Generate AI response incorporating scan results"""
        # Always use fallback response for now to avoid AI service errors
        # TODO: Fix AI chat service endpoint configuration
        logger.info("Generating response with scan results")
        
        # If no scan results, provide consultation response
        if not scan_results or all(not r.get('success') for r in scan_results.values()):
            return self._create_fallback_response(scan_results)
        
        # Build comprehensive response
        return self._create_detailed_response(user_message, target, scan_results)
    
    def _create_fallback_response(self, scan_results: Dict[str, Any]) -> str:
        """Create fallback response if AI fails"""
        if not scan_results:
            return "No scans were executed. Please specify a target URL or IP address."
        
        return self._create_detailed_response("Security scan", None, scan_results)
    
    def _create_detailed_response(
        self, 
        user_message: str, 
        target: Optional[str], 
        scan_results: Dict[str, Any]
    ) -> str:
        """Create detailed security analysis response"""
        response_parts = []
        
        # Header
        response_parts.append("🔒 **VULNERABILITY ASSESSMENT & PENETRATION TEST RESULTS**")
        response_parts.append("=" * 80)
        
        if target:
            response_parts.append(f"\n🎯 **Target**: {target}")
        
        response_parts.append(f"📅 **Scan Time**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        response_parts.append(f"🔧 **Tools Used**: {', '.join(scan_results.keys())}")
        response_parts.append("")
        
        # Summary statistics
        total_findings = 0
        successful_scans = 0
        total_duration = 0
        
        for tool, result in scan_results.items():
            if result.get('success'):
                successful_scans += 1
                total_findings += result.get('findings_count', 0)
                total_duration += result.get('duration', 0)
        
        response_parts.append(f"✅ **Successful Scans**: {successful_scans}/{len(scan_results)}")
        response_parts.append(f"🔍 **Total Findings**: {total_findings}")
        response_parts.append(f"⏱️ **Total Duration**: {total_duration:.1f}s")
        response_parts.append("")
        
        # Individual tool results
        response_parts.append("## 📊 DETAILED SCAN RESULTS")
        response_parts.append("")
        
        for tool, result in scan_results.items():
            response_parts.append(f"### {tool.upper()}")
            
            if result.get('success'):
                findings = result.get('findings_count', 0)
                duration = result.get('duration', 0)
                
                response_parts.append(f"- **Status**: ✅ Success")
                response_parts.append(f"- **Findings**: {findings}")
                response_parts.append(f"- **Duration**: {duration:.2f}s")
                
                # Add parsed results if available
                if 'parsed_results' in result and result['parsed_results'].get('findings'):
                    response_parts.append(f"- **Details**:")
                    findings_list = result['parsed_results']['findings']
                    
                    for idx, finding in enumerate(findings_list[:5], 1):  # Show top 5
                        if isinstance(finding, dict):
                            desc = finding.get('description', finding.get('title', 'Finding'))
                            severity = finding.get('severity', 'UNKNOWN')
                            response_parts.append(f"  {idx}. [{severity}] {desc}")
                        else:
                            response_parts.append(f"  {idx}. {finding}")
                    
                    if len(findings_list) > 5:
                        response_parts.append(f"  ... and {len(findings_list) - 5} more findings")
                
                elif findings > 0:
                    raw_output = result.get('raw_output', '')
                    if raw_output:
                        response_parts.append(f"- **Sample Output**: {raw_output[:200]}...")
                
            else:
                response_parts.append(f"- **Status**: ❌ Failed")
                response_parts.append(f"- **Error**: {result.get('error', 'Unknown error')}")
            
            response_parts.append("")
        
        # Risk assessment
        response_parts.append("## 🎯 RISK ASSESSMENT")
        response_parts.append("")
        
        if total_findings == 0:
            response_parts.append("✅ **Risk Level**: LOW")
            response_parts.append("No immediate vulnerabilities detected in this scan.")
        elif total_findings < 5:
            response_parts.append("⚠️ **Risk Level**: MEDIUM")
            response_parts.append(f"Found {total_findings} potential security issues. Review and remediate.")
        elif total_findings < 10:
            response_parts.append("🔴 **Risk Level**: HIGH")
            response_parts.append(f"Found {total_findings} security issues. Immediate attention required.")
        else:
            response_parts.append("🚨 **Risk Level**: CRITICAL")
            response_parts.append(f"Found {total_findings}+ security issues. Urgent remediation needed.")
        
        response_parts.append("")
        
        # Recommendations
        response_parts.append("## 💡 RECOMMENDATIONS")
        response_parts.append("")
        response_parts.append("1. Review all identified vulnerabilities in detail")
        response_parts.append("2. Prioritize critical and high-severity findings")
        response_parts.append("3. Implement security patches and configuration changes")
        response_parts.append("4. Conduct a full penetration test for comprehensive assessment")
        response_parts.append("5. Schedule regular security scans (weekly/monthly)")
        response_parts.append("")
        
        response_parts.append("=" * 80)
        response_parts.append("📋 **Full report available in the VAPT dashboard**")
        
        return "\n".join(response_parts)
    
    def _create_execution_summary(
        self,
        tools_executed: List[str],
        target: Optional[str],
        results: Dict[str, Any]
    ) -> str:
        """Create execution summary"""
        if not tools_executed:
            return "No tools executed"
        
        successful = sum(1 for r in results.values() if r.get('success'))
        failed = len(tools_executed) - successful
        total_findings = sum(
            r.get('findings_count', 0) for r in results.values() if r.get('success')
        )
        
        summary = f"Executed {len(tools_executed)} tools on {target or 'unknown target'}: "
        summary += f"{successful} successful, {failed} failed, {total_findings} total findings"
        
        return summary


# Global instance
_ai_chat_bridge = None


def get_ai_chat_bridge() -> AIChatToolBridge:
    """Get singleton instance of AI chat bridge"""
    global _ai_chat_bridge
    if _ai_chat_bridge is None:
        _ai_chat_bridge = AIChatToolBridge()
    return _ai_chat_bridge
