"""
Multi-Agent AI System
Week 7-8: LangChain-based agents for CVE analysis, exploit research, and recommendations

Agents:
- CVE Agent: Analyzes CVE severity, impact, affected products
- Exploit Agent: Finds related exploits, assesses exploitability
- Recommendation Agent: Provides mitigation advice and patches
- Coordinator Agent: Orchestrates multi-agent workflows
"""
import logging
import os
from typing import List, Dict, Optional, Any
from datetime import datetime

from langchain.agents import AgentExecutor, create_openai_functions_agent
from langchain.tools import BaseTool, StructuredTool
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain.schema import SystemMessage, HumanMessage, AIMessage
from langchain.memory import ConversationBufferMemory

from core.semantic_search import get_search_engine


logger = logging.getLogger(__name__)


class CVESearchTool(BaseTool):
    """Tool for searching CVE database"""
    
    name = "search_cves"
    description = """
    Search the CVE database for vulnerabilities.
    Input should be a search query describing the vulnerability.
    Returns relevant CVE entries with severity, CVSS scores, and descriptions.
    """
    
    def _run(self, query: str) -> str:
        """Search CVEs"""
        try:
            search_engine = get_search_engine()
            results = search_engine.search_cves(query, top_k=5)
            
            if not results:
                return "No CVEs found for this query."
            
            # Format results
            output = []
            for r in results:
                metadata = r.get('metadata', {})
                output.append(
                    f"CVE: {r['cve_id']}\n"
                    f"Severity: {metadata.get('severity', 'Unknown')}\n"
                    f"CVSS: {metadata.get('cvss_score', 'N/A')}\n"
                    f"Description: {r['description'][:200]}...\n"
                    f"Similarity: {r['similarity_score']:.2f}\n"
                )
            
            return "\n---\n".join(output)
            
        except Exception as e:
            logger.error(f"CVE search error: {e}")
            return f"Error searching CVEs: {str(e)}"
    
    async def _arun(self, query: str) -> str:
        """Async run"""
        return self._run(query)


class ExploitSearchTool(BaseTool):
    """Tool for searching exploit database"""
    
    name = "search_exploits"
    description = """
    Search the exploit database for proof-of-concept exploits.
    Input should be a CVE ID or vulnerability description.
    Returns available exploits with platform, type, and exploit details.
    """
    
    def _run(self, query: str) -> str:
        """Search exploits"""
        try:
            search_engine = get_search_engine()
            results = search_engine.search_exploits(query, top_k=5)
            
            if not results:
                return "No exploits found for this query."
            
            # Format results
            output = []
            for r in results:
                metadata = r.get('metadata', {})
                output.append(
                    f"Exploit: {r['exploit_id']}\n"
                    f"Platform: {metadata.get('platform', 'Unknown')}\n"
                    f"Type: {metadata.get('type', 'Unknown')}\n"
                    f"Description: {r['description'][:200]}...\n"
                    f"Similarity: {r['similarity_score']:.2f}\n"
                )
            
            return "\n---\n".join(output)
            
        except Exception as e:
            logger.error(f"Exploit search error: {e}")
            return f"Error searching exploits: {str(e)}"
    
    async def _arun(self, query: str) -> str:
        """Async run"""
        return self._run(query)


class SecurityKnowledgeTool(BaseTool):
    """Tool for searching security knowledge base"""
    
    name = "search_security_knowledge"
    description = """
    Search the security knowledge base for best practices, mitigation strategies, and security advisories.
    Input should be a security topic or vulnerability type.
    Returns relevant security guidance and recommendations.
    """
    
    def _run(self, query: str) -> str:
        """Search knowledge base"""
        try:
            search_engine = get_search_engine()
            results = search_engine.search_knowledge(query, top_k=3)
            
            if not results:
                return "No security knowledge found for this query."
            
            # Format results
            output = []
            for r in results:
                metadata = r.get('metadata', {})
                output.append(
                    f"Topic: {metadata.get('topic', 'General Security')}\n"
                    f"Content: {r['content'][:300]}...\n"
                    f"Similarity: {r['similarity_score']:.2f}\n"
                )
            
            return "\n---\n".join(output)
            
        except Exception as e:
            logger.error(f"Knowledge search error: {e}")
            return f"Error searching knowledge: {str(e)}"
    
    async def _arun(self, query: str) -> str:
        """Async run"""
        return self._run(query)


class CVEAgent:
    """Agent specialized in CVE analysis"""
    
    def __init__(self, llm: Optional[ChatOpenAI] = None):
        """Initialize CVE agent"""
        self.llm = llm or ChatOpenAI(
            model="gpt-4",
            temperature=0.2,
            openai_api_key=os.getenv("OPENAI_API_KEY")
        )
        
        self.tools = [
            CVESearchTool(),
            SecurityKnowledgeTool()
        ]
        
        self.system_prompt = """You are a CVE analysis expert. Your role is to:
1. Search and analyze CVE vulnerabilities
2. Assess severity and impact
3. Identify affected products and versions
4. Explain vulnerability details in clear terms
5. Provide CVSS score interpretation

When analyzing a CVE, always:
- Search the CVE database thoroughly
- Explain the technical details clearly
- Highlight the severity and risk level
- Identify affected systems
- Reference related security knowledge
"""
        
        logger.info("CVE Agent initialized")
    
    def analyze_cve(self, cve_id: str) -> Dict[str, Any]:
        """
        Analyze a specific CVE
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            Analysis results with severity, impact, recommendations
        """
        logger.info(f"CVE Agent analyzing: {cve_id}")
        
        # Create agent
        prompt = ChatPromptTemplate.from_messages([
            SystemMessage(content=self.system_prompt),
            HumanMessage(content=f"Analyze {cve_id} in detail. Provide severity, impact, and affected systems.")
        ])
        
        agent = create_openai_functions_agent(self.llm, self.tools, prompt)
        agent_executor = AgentExecutor(agent=agent, tools=self.tools, verbose=True)
        
        try:
            result = agent_executor.invoke({
                "input": f"Analyze CVE {cve_id}"
            })
            
            return {
                "cve_id": cve_id,
                "analysis": result['output'],
                "timestamp": datetime.now().isoformat(),
                "agent": "CVEAgent"
            }
            
        except Exception as e:
            logger.error(f"CVE analysis failed: {e}")
            return {
                "cve_id": cve_id,
                "error": str(e),
                "agent": "CVEAgent"
            }
    
    def find_related_cves(self, vulnerability_type: str) -> Dict[str, Any]:
        """
        Find CVEs related to a vulnerability type
        
        Args:
            vulnerability_type: Type of vulnerability (SQL injection, XSS, etc.)
            
        Returns:
            Related CVEs with analysis
        """
        logger.info(f"Finding CVEs for: {vulnerability_type}")
        
        prompt = ChatPromptTemplate.from_messages([
            SystemMessage(content=self.system_prompt),
            HumanMessage(content=f"Find and analyze CVEs related to {vulnerability_type}")
        ])
        
        agent = create_openai_functions_agent(self.llm, self.tools, prompt)
        agent_executor = AgentExecutor(agent=agent, tools=self.tools, verbose=True)
        
        try:
            result = agent_executor.invoke({
                "input": f"Find CVEs related to {vulnerability_type}"
            })
            
            return {
                "query": vulnerability_type,
                "results": result['output'],
                "timestamp": datetime.now().isoformat(),
                "agent": "CVEAgent"
            }
            
        except Exception as e:
            logger.error(f"CVE search failed: {e}")
            return {
                "query": vulnerability_type,
                "error": str(e),
                "agent": "CVEAgent"
            }


class ExploitAgent:
    """Agent specialized in exploit research"""
    
    def __init__(self, llm: Optional[ChatOpenAI] = None):
        """Initialize exploit agent"""
        self.llm = llm or ChatOpenAI(
            model="gpt-4",
            temperature=0.2,
            openai_api_key=os.getenv("OPENAI_API_KEY")
        )
        
        self.tools = [
            ExploitSearchTool(),
            CVESearchTool()
        ]
        
        self.system_prompt = """You are an exploit research expert. Your role is to:
1. Find available exploits for vulnerabilities
2. Assess exploitability and difficulty
3. Identify exploit techniques and requirements
4. Evaluate exploit reliability
5. Determine attack vectors and prerequisites

When researching exploits, always:
- Search exploit databases thoroughly
- Explain exploit mechanisms clearly
- Assess practical exploitability
- Identify required conditions
- Highlight security implications
"""
        
        logger.info("Exploit Agent initialized")
    
    def find_exploits_for_cve(self, cve_id: str) -> Dict[str, Any]:
        """
        Find available exploits for a CVE
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            Available exploits with analysis
        """
        logger.info(f"Exploit Agent searching for: {cve_id}")
        
        prompt = ChatPromptTemplate.from_messages([
            SystemMessage(content=self.system_prompt),
            HumanMessage(content=f"Find all available exploits for {cve_id}")
        ])
        
        agent = create_openai_functions_agent(self.llm, self.tools, prompt)
        agent_executor = AgentExecutor(agent=agent, tools=self.tools, verbose=True)
        
        try:
            result = agent_executor.invoke({
                "input": f"Find exploits for {cve_id}"
            })
            
            return {
                "cve_id": cve_id,
                "exploits": result['output'],
                "timestamp": datetime.now().isoformat(),
                "agent": "ExploitAgent"
            }
            
        except Exception as e:
            logger.error(f"Exploit search failed: {e}")
            return {
                "cve_id": cve_id,
                "error": str(e),
                "agent": "ExploitAgent"
            }
    
    def assess_exploitability(self, vulnerability_description: str) -> Dict[str, Any]:
        """
        Assess exploitability of a vulnerability
        
        Args:
            vulnerability_description: Description of the vulnerability
            
        Returns:
            Exploitability assessment
        """
        logger.info("Assessing exploitability")
        
        prompt = ChatPromptTemplate.from_messages([
            SystemMessage(content=self.system_prompt),
            HumanMessage(content=f"Assess exploitability: {vulnerability_description}")
        ])
        
        agent = create_openai_functions_agent(self.llm, self.tools, prompt)
        agent_executor = AgentExecutor(agent=agent, tools=self.tools, verbose=True)
        
        try:
            result = agent_executor.invoke({
                "input": f"Assess exploitability of: {vulnerability_description}"
            })
            
            return {
                "assessment": result['output'],
                "timestamp": datetime.now().isoformat(),
                "agent": "ExploitAgent"
            }
            
        except Exception as e:
            logger.error(f"Exploitability assessment failed: {e}")
            return {
                "error": str(e),
                "agent": "ExploitAgent"
            }


class RecommendationAgent:
    """Agent specialized in security recommendations"""
    
    def __init__(self, llm: Optional[ChatOpenAI] = None):
        """Initialize recommendation agent"""
        self.llm = llm or ChatOpenAI(
            model="gpt-4",
            temperature=0.3,
            openai_api_key=os.getenv("OPENAI_API_KEY")
        )
        
        self.tools = [
            SecurityKnowledgeTool(),
            CVESearchTool()
        ]
        
        self.system_prompt = """You are a security recommendation expert. Your role is to:
1. Provide mitigation strategies for vulnerabilities
2. Recommend security patches and updates
3. Suggest configuration changes
4. Advise on security best practices
5. Prioritize remediation actions

When making recommendations, always:
- Search security knowledge base
- Provide actionable steps
- Prioritize by severity and impact
- Consider practical implementation
- Reference industry standards
"""
        
        logger.info("Recommendation Agent initialized")
    
    def get_mitigation_advice(self, cve_id: str) -> Dict[str, Any]:
        """
        Get mitigation advice for a CVE
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            Mitigation recommendations
        """
        logger.info(f"Getting mitigation advice for: {cve_id}")
        
        prompt = ChatPromptTemplate.from_messages([
            SystemMessage(content=self.system_prompt),
            HumanMessage(content=f"Provide mitigation advice for {cve_id}")
        ])
        
        agent = create_openai_functions_agent(self.llm, self.tools, prompt)
        agent_executor = AgentExecutor(agent=agent, tools=self.tools, verbose=True)
        
        try:
            result = agent_executor.invoke({
                "input": f"Get mitigation advice for {cve_id}"
            })
            
            return {
                "cve_id": cve_id,
                "recommendations": result['output'],
                "timestamp": datetime.now().isoformat(),
                "agent": "RecommendationAgent"
            }
            
        except Exception as e:
            logger.error(f"Recommendation failed: {e}")
            return {
                "cve_id": cve_id,
                "error": str(e),
                "agent": "RecommendationAgent"
            }
    
    def prioritize_vulnerabilities(self, cve_list: List[str]) -> Dict[str, Any]:
        """
        Prioritize a list of vulnerabilities
        
        Args:
            cve_list: List of CVE IDs
            
        Returns:
            Prioritized list with recommendations
        """
        logger.info(f"Prioritizing {len(cve_list)} vulnerabilities")
        
        cves_str = ", ".join(cve_list)
        
        prompt = ChatPromptTemplate.from_messages([
            SystemMessage(content=self.system_prompt),
            HumanMessage(content=f"Prioritize these CVEs for remediation: {cves_str}")
        ])
        
        agent = create_openai_functions_agent(self.llm, self.tools, prompt)
        agent_executor = AgentExecutor(agent=agent, tools=self.tools, verbose=True)
        
        try:
            result = agent_executor.invoke({
                "input": f"Prioritize CVEs: {cves_str}"
            })
            
            return {
                "cve_list": cve_list,
                "prioritization": result['output'],
                "timestamp": datetime.now().isoformat(),
                "agent": "RecommendationAgent"
            }
            
        except Exception as e:
            logger.error(f"Prioritization failed: {e}")
            return {
                "cve_list": cve_list,
                "error": str(e),
                "agent": "RecommendationAgent"
            }


class CoordinatorAgent:
    """Coordinator agent that orchestrates multiple agents"""
    
    def __init__(self, llm: Optional[ChatOpenAI] = None):
        """Initialize coordinator"""
        self.llm = llm or ChatOpenAI(
            model="gpt-4",
            temperature=0.3,
            openai_api_key=os.getenv("OPENAI_API_KEY")
        )
        
        self.cve_agent = CVEAgent(self.llm)
        self.exploit_agent = ExploitAgent(self.llm)
        self.recommendation_agent = RecommendationAgent(self.llm)
        
        logger.info("Coordinator Agent initialized")
    
    def comprehensive_analysis(self, cve_id: str) -> Dict[str, Any]:
        """
        Perform comprehensive analysis using all agents
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            Complete analysis from all agents
        """
        logger.info(f"Coordinator performing comprehensive analysis: {cve_id}")
        
        results = {
            "cve_id": cve_id,
            "timestamp": datetime.now().isoformat(),
            "agents_used": ["CVEAgent", "ExploitAgent", "RecommendationAgent"]
        }
        
        # CVE Analysis
        logger.info("Step 1: CVE Analysis")
        cve_analysis = self.cve_agent.analyze_cve(cve_id)
        results['cve_analysis'] = cve_analysis
        
        # Exploit Research
        logger.info("Step 2: Exploit Research")
        exploit_research = self.exploit_agent.find_exploits_for_cve(cve_id)
        results['exploit_research'] = exploit_research
        
        # Recommendations
        logger.info("Step 3: Mitigation Recommendations")
        recommendations = self.recommendation_agent.get_mitigation_advice(cve_id)
        results['recommendations'] = recommendations
        
        # Generate summary
        results['summary'] = self._generate_summary(results)
        
        return results
    
    def _generate_summary(self, analysis: Dict[str, Any]) -> str:
        """Generate executive summary of analysis"""
        summary = f"Comprehensive Analysis for {analysis['cve_id']}\n\n"
        
        if 'cve_analysis' in analysis and 'analysis' in analysis['cve_analysis']:
            summary += "CVE Analysis:\n" + analysis['cve_analysis']['analysis'][:200] + "...\n\n"
        
        if 'exploit_research' in analysis and 'exploits' in analysis['exploit_research']:
            summary += "Exploits Found:\n" + analysis['exploit_research']['exploits'][:200] + "...\n\n"
        
        if 'recommendations' in analysis and 'recommendations' in analysis['recommendations']:
            summary += "Recommendations:\n" + analysis['recommendations']['recommendations'][:200] + "...\n"
        
        return summary


# Global instances
_cve_agent: Optional[CVEAgent] = None
_exploit_agent: Optional[ExploitAgent] = None
_recommendation_agent: Optional[RecommendationAgent] = None
_coordinator: Optional[CoordinatorAgent] = None


def get_cve_agent() -> CVEAgent:
    """Get CVE agent singleton"""
    global _cve_agent
    if _cve_agent is None:
        _cve_agent = CVEAgent()
    return _cve_agent


def get_exploit_agent() -> ExploitAgent:
    """Get exploit agent singleton"""
    global _exploit_agent
    if _exploit_agent is None:
        _exploit_agent = ExploitAgent()
    return _exploit_agent


def get_recommendation_agent() -> RecommendationAgent:
    """Get recommendation agent singleton"""
    global _recommendation_agent
    if _recommendation_agent is None:
        _recommendation_agent = RecommendationAgent()
    return _recommendation_agent


def get_coordinator() -> CoordinatorAgent:
    """Get coordinator singleton"""
    global _coordinator
    if _coordinator is None:
        _coordinator = CoordinatorAgent()
    return _coordinator
