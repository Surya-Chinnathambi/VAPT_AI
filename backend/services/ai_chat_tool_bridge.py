"""
AI Chat to Real-Time Security Scanning Bridge
Connects AI chat messages to Docker-based security tools execution
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
from core.ai_security_prompts import get_system_prompt

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
        
        # Tool trigger keywords mapping
        self.tool_keywords = {
            'nmap': ['scan', 'port', 'nmap', 'network', 'service detection'],
            'nikto': ['nikto', 'web scan', 'web vulnerabilities', 'http'],
            'nuclei': ['nuclei', 'template', 'multiple vulnerabilities'],
            'sqlmap': ['sql injection', 'sqlmap', 'database', 'sql'],
            'wpscan': ['wordpress', 'wp', 'wpscan', 'cms'],
            'testssl': ['ssl', 'tls', 'certificate', 'https', 'testssl'],
            'gobuster': ['directory', 'gobuster', 'brute force', 'files'],
            'sublist3r': ['subdomain', 'sublist3r', 'dns'],
            'amass': ['amass', 'recon', 'asset discovery'],
            'zaproxy': ['zap', 'web app', 'proxy', 'spider'],
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
        
        # Step 4: Execute tools if target detected (only if Docker is available)
        scan_results = {}
        if target and tools_to_execute and self.tool_executor.docker_available:
            logger.info(f"Target: {target}, Tools: {tools_to_execute}, Type: {scan_type}")
            
            # Notify user that scan is starting
            if progress_callback:
                await progress_callback({
                    "type": "scan_initiated",
                    "target": target,
                    "tools": tools_to_execute,
                    "scan_type": scan_type
                })
            
            # Execute tools in parallel
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
        elif target and tools_to_execute and not self.tool_executor.docker_available:
            logger.warning("Docker not available - skipping tool execution")
            scan_results = {
                "error": "Docker not available",
                "message": "Security scanning tools require Docker access. Please configure Docker socket mounting."
            }
        
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
        """Execute multiple tools in parallel"""
        logger.info(f"Executing {len(tools)} tools on {target}")
        
        tasks = []
        for tool in tools:
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
        # Build context with scan results
        context_parts = [f"User request: {user_message}"]
        
        if target:
            context_parts.append(f"Target analyzed: {target}")
        
        if scan_results:
            context_parts.append("\n=== SCAN RESULTS ===")
            for tool, result in scan_results.items():
                if result.get('success'):
                    findings_count = result.get('findings_count', 0)
                    context_parts.append(
                        f"\n{tool.upper()}: {findings_count} findings, "
                        f"Duration: {result.get('duration', 0):.1f}s"
                    )
                    
                    # Add parsed results
                    if 'parsed_results' in result:
                        parsed = result['parsed_results']
                        context_parts.append(f"  Details: {json.dumps(parsed, indent=2)}")
                else:
                    context_parts.append(f"\n{tool.upper()}: Failed - {result.get('error')}")
        
        context = "\n".join(context_parts)
        
        # Generate AI response
        try:
            response = await self.chat_service.chat(
                message=f"{user_message}\n\nBased on the scan results above, provide a comprehensive security analysis.",
                history=None,
                context=context
            )
            return response.get('response', 'Scan completed. Check results above.')
        
        except Exception as e:
            logger.error(f"AI response generation failed: {e}")
            return self._create_fallback_response(scan_results)
    
    def _create_fallback_response(self, scan_results: Dict[str, Any]) -> str:
        """Create fallback response if AI fails"""
        if not scan_results:
            return "No scans were executed. Please specify a target URL or IP address."
        
        response_parts = ["✅ Security scan completed:\n"]
        
        for tool, result in scan_results.items():
            if result.get('success'):
                findings = result.get('findings_count', 0)
                response_parts.append(
                    f"- {tool.upper()}: {findings} findings ({result.get('duration', 0):.1f}s)"
                )
            else:
                response_parts.append(f"- {tool.upper()}: Failed")
        
        total_findings = sum(
            r.get('findings_count', 0) for r in scan_results.values() if r.get('success')
        )
        
        response_parts.append(f"\nTotal findings: {total_findings}")
        response_parts.append("Review detailed results in the dashboard.")
        
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
