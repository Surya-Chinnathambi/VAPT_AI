"""
AI VAPT Training Integration
Integrates expanded scenarios with tool executor and training manager
"""

import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging

from .scenario_generator import (
    LEVEL_1_EXPANDED_SCENARIOS,
    LEVEL_2_EXPANDED_SCENARIOS,
    LEVEL_3_EXPANDED_SCENARIOS
)
from .tool_executor import get_tool_executor
from .training_manager import TrainingManager
from .performance_tracker import AIVAPTPerformanceTracker

logger = logging.getLogger(__name__)


class EnhancedTrainingManager:
    """Enhanced training manager with tool integration"""
    
    def __init__(self):
        self.tool_executor = get_tool_executor()
        self.training_manager = TrainingManager()
        self.performance_tracker = AIVAPTPerformanceTracker()
        
        # Load all scenarios
        self.all_scenarios = {
            "level1": LEVEL_1_EXPANDED_SCENARIOS,
            "level2": LEVEL_2_EXPANDED_SCENARIOS,
            "level3": LEVEL_3_EXPANDED_SCENARIOS
        }
        
        logger.info(f"Loaded scenarios: L1={len(self.all_scenarios['level1'])}, "
                   f"L2={len(self.all_scenarios['level2'])}, "
                   f"L3={len(self.all_scenarios['level3'])}")
    
    async def execute_scenario_with_tools(
        self,
        scenario: Dict[str, Any],
        level: str
    ) -> Dict[str, Any]:
        """
        Execute a training scenario with real tools
        
        Args:
            scenario: Scenario configuration
            level: Training level (level1, level2, level3)
        
        Returns:
            Execution results with AI output and tool results
        """
        
        logger.info(f"Executing scenario {scenario['scenario_id']}: {scenario['task']}")
        
        start_time = datetime.now()
        
        try:
            # Step 1: Get AI agent's plan
            ai_plan = await self._get_ai_plan(scenario, level)
            
            # Step 2: Execute tools based on scenario
            tool_results = await self._execute_scenario_tools(scenario, ai_plan)
            
            # Step 3: Get AI analysis of results
            ai_analysis = await self._get_ai_analysis(scenario, tool_results)
            
            # Step 4: Evaluate performance
            execution_time = (datetime.now() - start_time).total_seconds()
            performance = self._evaluate_performance(
                scenario,
                ai_plan,
                tool_results,
                ai_analysis,
                execution_time
            )
            
            return {
                "scenario_id": scenario["scenario_id"],
                "success": True,
                "execution_time": execution_time,
                "ai_plan": ai_plan,
                "tool_results": tool_results,
                "ai_analysis": ai_analysis,
                "performance": performance
            }
        
        except Exception as e:
            logger.error(f"Scenario execution failed: {str(e)}")
            return {
                "scenario_id": scenario["scenario_id"],
                "success": False,
                "error": str(e),
                "execution_time": (datetime.now() - start_time).total_seconds()
            }
    
    async def _get_ai_plan(
        self,
        scenario: Dict[str, Any],
        level: str
    ) -> Dict[str, Any]:
        """Get AI agent's execution plan"""
        
        prompt = f"""
You are a security testing AI agent at {level}.

TASK: {scenario['task']}
DIFFICULTY: {scenario['difficulty']}
INPUT: {scenario['input']}

SUGGESTED STEPS:
{chr(10).join(f"{i+1}. {step}" for i, step in enumerate(scenario['steps']))}

Generate a detailed execution plan including:
1. Tools to use (nmap, nuclei, nikto, sqlmap, etc.)
2. Specific commands with parameters
3. Expected findings
4. Success criteria

Respond in JSON format:
{{
    "tools": ["tool1", "tool2"],
    "commands": [{{"tool": "nmap", "parameters": "..."}}],
    "expected_findings": ["finding1", "finding2"],
    "success_criteria": ["criterion1", "criterion2"]
}}
"""
        
        # Get AI response from training manager
        response = await self.training_manager.llm.ainvoke(prompt)
        
        # Parse JSON response
        import json
        try:
            plan = json.loads(response.content)
            return plan
        except json.JSONDecodeError:
            # Fallback to basic plan
            return {
                "tools": self._extract_tools_from_steps(scenario['steps']),
                "commands": [],
                "expected_findings": [],
                "success_criteria": list(scenario.get('success_metrics', {}).keys())
            }
    
    def _extract_tools_from_steps(self, steps: List[str]) -> List[str]:
        """Extract tool names from scenario steps"""
        tools = []
        tool_keywords = {
            "nmap": "nmap",
            "sublist3r": "sublist3r",
            "amass": "amass",
            "nuclei": "nuclei",
            "nikto": "nikto",
            "testssl": "testssl",
            "sqlmap": "sqlmap",
            "whois": "whois",
            "dig": "dig"
        }
        
        for step in steps:
            step_lower = step.lower()
            for keyword, tool_name in tool_keywords.items():
                if keyword in step_lower and tool_name not in tools:
                    tools.append(tool_name)
        
        return tools
    
    async def _execute_scenario_tools(
        self,
        scenario: Dict[str, Any],
        ai_plan: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute tools for scenario"""
        
        results = {}
        tools = ai_plan.get("tools", [])
        
        # Parse scenario input to extract target
        scenario_input = scenario.get("input", "")
        target = self._extract_target_from_input(scenario_input)
        
        if not target:
            logger.warning("No target extracted from scenario input")
            return {"error": "No target specified"}
        
        # Execute tools based on scenario
        for tool in tools:
            try:
                if tool == "nmap":
                    results["nmap"] = await self.tool_executor.run_nmap(
                        target,
                        scan_type="quick"
                    )
                
                elif tool == "sublist3r":
                    domain = self._extract_domain(target)
                    if domain:
                        results["sublist3r"] = await self.tool_executor.run_sublist3r(domain)
                
                elif tool == "amass":
                    domain = self._extract_domain(target)
                    if domain:
                        results["amass"] = await self.tool_executor.run_amass(domain)
                
                elif tool == "nuclei":
                    results["nuclei"] = await self.tool_executor.run_nuclei(
                        target,
                        severity=["critical", "high", "medium"]
                    )
                
                elif tool == "nikto":
                    results["nikto"] = await self.tool_executor.run_nikto(target)
                
                elif tool == "testssl":
                    results["testssl"] = await self.tool_executor.run_testssl(target)
                
                elif tool == "whois":
                    domain = self._extract_domain(target)
                    if domain:
                        results["whois"] = await self.tool_executor.run_whois(domain)
                
                elif tool == "dig":
                    domain = self._extract_domain(target)
                    if domain:
                        results["dig"] = await self.tool_executor.run_dig(domain)
            
            except Exception as e:
                logger.error(f"Tool {tool} execution failed: {str(e)}")
                results[tool] = {"error": str(e)}
        
        return results
    
    def _extract_target_from_input(self, input_text: str) -> Optional[str]:
        """Extract target URL/IP/domain from scenario input"""
        import re
        
        # Try to extract URL
        url_pattern = r'https?://[^\s]+'
        url_match = re.search(url_pattern, input_text)
        if url_match:
            return url_match.group(0)
        
        # Try to extract domain
        domain_pattern = r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        domain_match = re.search(domain_pattern, input_text)
        if domain_match:
            return domain_match.group(0)
        
        # Try to extract IP
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        ip_match = re.search(ip_pattern, input_text)
        if ip_match:
            return ip_match.group(0)
        
        return None
    
    def _extract_domain(self, target: str) -> Optional[str]:
        """Extract domain from URL or target string"""
        import re
        from urllib.parse import urlparse
        
        # If it's a URL, parse it
        if target.startswith("http://") or target.startswith("https://"):
            parsed = urlparse(target)
            return parsed.netloc
        
        # If it's already a domain
        domain_pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(domain_pattern, target):
            return target
        
        return None
    
    async def _get_ai_analysis(
        self,
        scenario: Dict[str, Any],
        tool_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Get AI analysis of tool results"""
        
        prompt = f"""
You are analyzing security testing results.

SCENARIO: {scenario['task']}
EXPECTED OUTPUT: {scenario.get('expected_output', {})}
SUCCESS METRICS: {scenario.get('success_metrics', {})}

TOOL RESULTS:
{self._format_tool_results(tool_results)}

Analyze the results and provide:
1. Summary of findings
2. Comparison with expected output
3. Success/failure determination
4. Recommendations

Respond in JSON format:
{{
    "summary": "...",
    "findings": ["finding1", "finding2"],
    "meets_expectations": true/false,
    "success_rate": 0.0-1.0,
    "recommendations": ["rec1", "rec2"]
}}
"""
        
        response = await self.training_manager.llm.ainvoke(prompt)
        
        import json
        try:
            analysis = json.loads(response.content)
            return analysis
        except json.JSONDecodeError:
            return {
                "summary": response.content[:200],
                "findings": [],
                "meets_expectations": False,
                "success_rate": 0.0,
                "recommendations": []
            }
    
    def _format_tool_results(self, tool_results: Dict[str, Any]) -> str:
        """Format tool results for AI analysis"""
        import json
        return json.dumps(tool_results, indent=2)[:1000]  # Truncate
    
    def _evaluate_performance(
        self,
        scenario: Dict[str, Any],
        ai_plan: Dict[str, Any],
        tool_results: Dict[str, Any],
        ai_analysis: Dict[str, Any],
        execution_time: float
    ) -> Dict[str, Any]:
        """Evaluate AI performance on scenario"""
        
        # Calculate scores
        plan_quality = self._score_plan_quality(ai_plan, scenario)
        tool_usage = self._score_tool_usage(tool_results, ai_plan)
        analysis_quality = self._score_analysis_quality(ai_analysis, scenario)
        time_efficiency = self._score_time_efficiency(execution_time, scenario)
        
        overall_score = (
            plan_quality * 0.3 +
            tool_usage * 0.3 +
            analysis_quality * 0.3 +
            time_efficiency * 0.1
        )
        
        return {
            "overall_score": overall_score,
            "plan_quality": plan_quality,
            "tool_usage": tool_usage,
            "analysis_quality": analysis_quality,
            "time_efficiency": time_efficiency,
            "passed": overall_score >= 0.85  # 85% threshold
        }
    
    def _score_plan_quality(self, ai_plan: Dict[str, Any], scenario: Dict[str, Any]) -> float:
        """Score the quality of AI's execution plan"""
        score = 0.0
        
        # Check if correct tools were selected
        expected_tools = self._extract_tools_from_steps(scenario['steps'])
        selected_tools = ai_plan.get('tools', [])
        
        if expected_tools:
            tool_overlap = len(set(expected_tools) & set(selected_tools)) / len(expected_tools)
            score += tool_overlap * 0.5
        
        # Check if plan has commands
        if ai_plan.get('commands'):
            score += 0.3
        
        # Check if success criteria defined
        if ai_plan.get('success_criteria'):
            score += 0.2
        
        return min(score, 1.0)
    
    def _score_tool_usage(self, tool_results: Dict[str, Any], ai_plan: Dict[str, Any]) -> float:
        """Score tool execution success"""
        if not tool_results:
            return 0.0
        
        successful_tools = sum(
            1 for result in tool_results.values()
            if isinstance(result, dict) and "error" not in result
        )
        
        total_tools = len(tool_results)
        
        return successful_tools / total_tools if total_tools > 0 else 0.0
    
    def _score_analysis_quality(self, ai_analysis: Dict[str, Any], scenario: Dict[str, Any]) -> float:
        """Score AI's analysis of results"""
        score = 0.0
        
        # Check if summary present
        if ai_analysis.get('summary'):
            score += 0.3
        
        # Check if findings identified
        if ai_analysis.get('findings'):
            score += 0.3
        
        # Check if recommendations provided
        if ai_analysis.get('recommendations'):
            score += 0.2
        
        # Check if success rate calculated
        if 'success_rate' in ai_analysis:
            score += 0.2
        
        return min(score, 1.0)
    
    def _score_time_efficiency(self, execution_time: float, scenario: Dict[str, Any]) -> float:
        """Score execution time efficiency"""
        expected_duration = scenario.get('expected_duration', '5-10 minutes')
        
        # Parse expected duration
        import re
        match = re.search(r'(\d+)-(\d+)', expected_duration)
        if match:
            min_time = int(match.group(1)) * 60
            max_time = int(match.group(2)) * 60
            avg_time = (min_time + max_time) / 2
            
            # Score based on how close to average
            if execution_time <= avg_time:
                return 1.0
            elif execution_time <= max_time:
                return 0.8
            elif execution_time <= max_time * 1.5:
                return 0.6
            else:
                return 0.4
        
        return 0.7  # Default score if can't parse
    
    async def run_training_batch(
        self,
        level: str,
        num_scenarios: int = 10,
        scenario_filter: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Run a batch of training scenarios
        
        Args:
            level: Training level (level1, level2, level3)
            num_scenarios: Number of scenarios to run
            scenario_filter: Filter scenarios by criteria
        
        Returns:
            Batch execution results
        """
        
        scenarios = self.all_scenarios.get(level, [])
        
        # Apply filters
        if scenario_filter:
            scenarios = [s for s in scenarios if self._matches_filter(s, scenario_filter)]
        
        # Limit to requested number
        scenarios = scenarios[:num_scenarios]
        
        logger.info(f"Running {len(scenarios)} scenarios for {level}")
        
        results = []
        for scenario in scenarios:
            result = await self.execute_scenario_with_tools(scenario, level)
            results.append(result)
            
            # Track performance
            if result.get('performance'):
                self.performance_tracker.record_scenario_result(
                    scenario['scenario_id'],
                    result['performance']['overall_score']
                )
        
        # Calculate batch metrics
        successful = sum(1 for r in results if r.get('success', False))
        avg_score = sum(
            r.get('performance', {}).get('overall_score', 0)
            for r in results
        ) / len(results) if results else 0.0
        
        return {
            "level": level,
            "total_scenarios": len(results),
            "successful": successful,
            "success_rate": successful / len(results) if results else 0.0,
            "average_score": avg_score,
            "results": results,
            "ready_for_advancement": avg_score >= 0.85
        }
    
    def _matches_filter(self, scenario: Dict[str, Any], filter_criteria: Dict[str, Any]) -> bool:
        """Check if scenario matches filter criteria"""
        for key, value in filter_criteria.items():
            if key not in scenario or scenario[key] != value:
                return False
        return True


# Singleton instance
_enhanced_training_manager = None


def get_enhanced_training_manager() -> EnhancedTrainingManager:
    """Get singleton EnhancedTrainingManager instance"""
    global _enhanced_training_manager
    if _enhanced_training_manager is None:
        _enhanced_training_manager = EnhancedTrainingManager()
    return _enhanced_training_manager
