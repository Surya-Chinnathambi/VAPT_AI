"""
AI Chat Service with Azure OpenAI GPT-5
Handles security-focused chat with tool orchestration
"""
import os
import json
import logging
from typing import List, Dict, Any, Optional
from openai import AzureOpenAI
from config import (
    AZURE_OPENAI_KEY, 
    AZURE_OPENAI_ENDPOINT, 
    AZURE_OPENAI_API_VERSION,
    AZURE_OPENAI_DEPLOYMENT
)

logger = logging.getLogger(__name__)

SECURITY_SYSTEM_PROMPT = """You are an expert cybersecurity AI assistant specializing in:

**Core Competencies:**
- Network security analysis and threat assessment
- Vulnerability identification and remediation strategies
- Penetration testing methodologies (OWASP, NIST, PTES)
- CVE analysis and risk evaluation with CVSS scoring
- Security compliance frameworks (OWASP Top 10, PCI-DSS, HIPAA, ISO 27001, NIST CSF, GDPR, SOC2)
- Incident response and digital forensics
- Security architecture and defense-in-depth strategies
- Exploit analysis and mitigation techniques

**Communication Style:**
1. Provide detailed, actionable security advice
2. Explain technical concepts clearly for both technical and non-technical audiences
3. Always include risk levels (Critical/High/Medium/Low) when discussing vulnerabilities
4. Reference relevant CVEs, CWEs, and compliance standards
5. Suggest specific remediation steps with priority ordering
6. Include code examples or configuration snippets when helpful

**Tool Usage:**
You have access to these security tools:
- `scan_ports`: Scan network ports on a target
- `scan_web`: Scan web applications for vulnerabilities
- `search_cves`: Search CVE database by keyword
- `search_shodan`: Query Shodan for internet-exposed services
- `search_exploits`: Find exploits in Exploit-DB
- `map_compliance`: Map vulnerabilities to compliance frameworks

When a user asks for a scan or search, use the appropriate tool.

**Ethical Guidelines:**
- Always prioritize ethical security practices
- Promote responsible disclosure
- Never provide guidance for malicious activities
- Emphasize authorization requirements for security testing
- Recommend legal and ethical approaches only

**Response Format for Vulnerability Analysis:**
1. **Summary**: Brief description
2. **Risk Level**: Critical/High/Medium/Low + CVSS score if applicable
3. **Impact**: What could an attacker do?
4. **Remediation**: Step-by-step fix
5. **References**: CVEs, documentation, best practices
6. **Compliance**: Relevant standards violated

Be concise but comprehensive. Security is critical."""

class AIChatService:
    def __init__(self):
        """Initialize Azure OpenAI client"""
        self.client = None
        if AZURE_OPENAI_KEY and AZURE_OPENAI_ENDPOINT:
            try:
                self.client = AzureOpenAI(
                    api_key=AZURE_OPENAI_KEY,
                    api_version=AZURE_OPENAI_API_VERSION,
                    azure_endpoint=AZURE_OPENAI_ENDPOINT
                )
                logger.info("Azure OpenAI client initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize Azure OpenAI: {e}")
        else:
            logger.warning("Azure OpenAI credentials not configured")
    
    def is_available(self) -> bool:
        """Check if AI service is available"""
        return self.client is not None
    
    async def chat(
        self, 
        message: str, 
        history: Optional[List[Dict[str, str]]] = None,
        context: Optional[str] = None,
        tools: Optional[List[Dict]] = None
    ) -> Dict[str, Any]:
        """
        Send a chat message and get AI response
        
        Args:
            message: User's message
            history: Previous chat messages
            context: Additional context (scan results, etc.)
            tools: Available tools for function calling
        
        Returns:
            Dict with response, tool_calls, etc.
        """
        if not self.is_available():
            return {
                "error": "AI service not configured. Please add Azure OpenAI credentials.",
                "response": "I'm sorry, but AI chat is not available. Please configure Azure OpenAI API keys."
            }
        
        try:
            # Build messages
            messages = [{"role": "system", "content": SECURITY_SYSTEM_PROMPT}]
            
            # Add context if provided
            if context:
                messages.append({
                    "role": "system",
                    "content": f"Additional Context:\n{context}"
                })
            
            # Add conversation history
            if history:
                messages.extend(history)
            
            # Add current message
            messages.append({"role": "user", "content": message})
            
            # Prepare request parameters
            request_params = {
                "model": AZURE_OPENAI_DEPLOYMENT,
                "messages": messages,
                "temperature": 0.7,
                "max_tokens": 2000,
                "top_p": 0.95,
                "frequency_penalty": 0,
                "presence_penalty": 0
            }
            
            # Add tools if provided
            if tools:
                request_params["tools"] = tools
                request_params["tool_choice"] = "auto"
            
            # Get completion
            response = self.client.chat.completions.create(**request_params)
            
            # Extract response
            choice = response.choices[0]
            message_content = choice.message
            
            result = {
                "response": message_content.content or "",
                "finish_reason": choice.finish_reason,
                "usage": {
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens
                }
            }
            
            # Handle tool calls
            if hasattr(message_content, 'tool_calls') and message_content.tool_calls:
                result["tool_calls"] = [
                    {
                        "id": tool_call.id,
                        "function": tool_call.function.name,
                        "arguments": json.loads(tool_call.function.arguments)
                    }
                    for tool_call in message_content.tool_calls
                ]
            
            return result
            
        except Exception as e:
            logger.error(f"Chat error: {e}")
            return {
                "error": str(e),
                "response": f"I encountered an error: {str(e)}"
            }
    
    async def analyze_scan_results(
        self, 
        scan_type: str, 
        results: Dict[str, Any],
        compliance_frameworks: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Analyze scan results and provide security recommendations
        
        Args:
            scan_type: Type of scan (port_scan, web_scan, etc.)
            results: Raw scan results
            compliance_frameworks: Frameworks to check against
        
        Returns:
            AI analysis with recommendations
        """
        if not self.is_available():
            return {"error": "AI service not configured"}
        
        try:
            # Create analysis prompt
            prompt = f"""Analyze these {scan_type} results and provide a comprehensive security assessment:

**Scan Type:** {scan_type}

**Results:**
{json.dumps(results, indent=2)}

Please provide:
1. **Executive Summary** - Brief overview of findings
2. **Critical Findings** - Most severe issues that need immediate attention
3. **Risk Assessment** - Overall risk level and scoring
4. **Detailed Analysis** - Each vulnerability with CVSS scores
5. **Remediation Plan** - Prioritized action items
6. **Compliance Impact** - Which standards are affected{f" (focus on: {', '.join(compliance_frameworks)})" if compliance_frameworks else ""}

Format your response in clear sections with markdown."""

            response = await self.chat(
                message=prompt,
                context="This is an automated scan analysis request"
            )
            
            return {
                "analysis": response.get("response", ""),
                "summary": self._extract_summary(response.get("response", "")),
                "risk_level": self._determine_risk_level(results),
                "compliance_issues": self._extract_compliance_issues(response.get("response", ""))
            }
            
        except Exception as e:
            logger.error(f"Scan analysis error: {e}")
            return {"error": str(e)}
    
    def _extract_summary(self, analysis: str) -> str:
        """Extract executive summary from analysis"""
        lines = analysis.split('\n')
        summary_lines = []
        in_summary = False
        
        for line in lines:
            if 'executive summary' in line.lower():
                in_summary = True
                continue
            if in_summary:
                if line.startswith('#') and summary_lines:
                    break
                if line.strip():
                    summary_lines.append(line.strip())
        
        return ' '.join(summary_lines[:3]) if summary_lines else analysis[:200]
    
    def _determine_risk_level(self, results: Dict[str, Any]) -> str:
        """Determine overall risk level from scan results"""
        if 'open_ports' in results:
            open_count = len(results.get('open_ports', []))
            if open_count > 20:
                return "high"
            elif open_count > 10:
                return "medium"
            else:
                return "low"
        
        if 'vulnerabilities' in results:
            vulns = results.get('vulnerabilities', [])
            critical_count = sum(1 for v in vulns if v.get('severity') == 'critical')
            high_count = sum(1 for v in vulns if v.get('severity') == 'high')
            
            if critical_count > 0:
                return "critical"
            elif high_count > 0:
                return "high"
            elif len(vulns) > 0:
                return "medium"
        
        return "low"
    
    def _extract_compliance_issues(self, analysis: str) -> List[str]:
        """Extract compliance issues mentioned in analysis"""
        compliance_keywords = [
            'PCI-DSS', 'HIPAA', 'GDPR', 'SOC2', 'ISO 27001', 
            'NIST', 'OWASP', 'CIS'
        ]
        
        issues = []
        for keyword in compliance_keywords:
            if keyword in analysis:
                issues.append(keyword)
        
        return issues

# Global instance
_chat_service = None

def get_chat_service() -> AIChatService:
    """Get or create chat service instance"""
    global _chat_service
    if _chat_service is None:
        _chat_service = AIChatService()
    return _chat_service
