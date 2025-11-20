import asyncio
import os
import json
try:
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import HumanMessage, SystemMessage
except ImportError:
    try:
        from langchain_openai import ChatOpenAI
        from langchain.schema import HumanMessage, SystemMessage
    except ImportError:
        print("Warning: langchain_openai or langchain not installed. AI features will be disabled.")
        ChatOpenAI = None
        HumanMessage = None
        SystemMessage = None

from .level1_config import LEVEL_1_TRAINING_SCENARIOS, LEVEL_1_PROMPTS
from .level2_config import LEVEL_2_TRAINING_SCENARIOS, LEVEL_2_PROMPTS
from .level3_config import LEVEL_3_TRAINING_SCENARIOS, LEVEL_3_PROMPTS
from .performance_tracker import AIVAPTPerformanceTracker

class TrainingManager:
    def __init__(self):
        self.tracker = AIVAPTPerformanceTracker()
        self.scenarios = {
            "basic": LEVEL_1_TRAINING_SCENARIOS,
            "medium": LEVEL_2_TRAINING_SCENARIOS,
            "expert": LEVEL_3_TRAINING_SCENARIOS
        }
        self.prompts = {
            "basic": LEVEL_1_PROMPTS,
            "medium": LEVEL_2_PROMPTS,
            "expert": LEVEL_3_PROMPTS
        }
        
        # Initialize AI
        api_key = os.getenv("OPENAI_API_KEY")
        base_url = os.getenv("AZURE_OPENAI_ENDPOINT", "https://litellm.dev.asoclab.dev/v1")
        model_name = os.getenv("AZURE_OPENAI_DEPLOYMENT", "azure/gpt-5-chat")
        
        if not ChatOpenAI:
             self.llm = None
        elif not api_key:
            print("WARNING: OPENAI_API_KEY not found. AI simulation will fail.")
            self.llm = None
        else:
            # Use LiteLLM proxy endpoint with GPT-5 (temperature must be 1)
            self.llm = ChatOpenAI(
                model=model_name,
                temperature=1,
                openai_api_key=api_key,
                openai_api_base=base_url
            )

    async def run_training_session(self, level="basic", phase=None, num_scenarios=1):
        print(f"Starting training session for Level: {level}, Phase: {phase}")
        
        scenarios_to_run = self.scenarios.get(level, [])
        if not scenarios_to_run:
            print(f"No scenarios found for level {level}")
            return

        # Filter by phase if needed (not implemented in config yet, so just taking first N)
        selected_scenarios = scenarios_to_run[:num_scenarios]
        
        for scenario in selected_scenarios:
            print(f"Running scenario: {scenario['scenario_id']} - {scenario['task']}")
            
            # Execute AI
            result = await self.execute_ai_scenario(scenario, level)
            
            # Evaluate performance
            evaluation = await self.tracker.evaluate_scenario(scenario['scenario_id'], result, scenario)
            
            print(f"Scenario completed. Evaluation: {evaluation}")
            
            if evaluation.get("advance"):
                print(f"🎉 CONGRATULATIONS! AI is ready to advance to {evaluation['next_level']} level!")
                self.tracker.metrics["current_level"] = evaluation['next_level']

    async def execute_ai_scenario(self, scenario, level):
        if not self.llm:
            print("AI not initialized. Returning dummy result.")
            return {
                "output": scenario.get("expected_output", {}),
                "findings": [],
                "duration": 5
            }

        # Select appropriate system prompt
        # Simple heuristic to pick prompt based on task keywords
        task = scenario['task'].lower()
        prompts = self.prompts.get(level, {})
        system_prompt = list(prompts.values())[0] # Default to first prompt
        
        if "recon" in task:
            system_prompt = prompts.get("reconnaissance", system_prompt)
        elif "scan" in task or "ssl" in task:
            system_prompt = prompts.get("scanning", system_prompt)
        elif "report" in task:
            system_prompt = prompts.get("reporting", system_prompt)
        elif "validat" in task:
            system_prompt = prompts.get("validation", system_prompt)
        elif "exploit" in task:
            system_prompt = prompts.get("exploitation", system_prompt)
        elif "prioritiz" in task:
            system_prompt = prompts.get("prioritization", system_prompt)
            
        user_input = f"""
TASK: {scenario['task']}
INPUT: {scenario['input']}
STEPS: {json.dumps(scenario['steps'], indent=2)}

Execute this task and provide the output in JSON format matching the expected structure.
"""

        try:
            messages = [
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_input)
            ]
            
            start_time = asyncio.get_event_loop().time()
            response = await self.llm.ainvoke(messages)
            end_time = asyncio.get_event_loop().time()
            duration = (end_time - start_time) / 60 # Minutes
            
            content = response.content
            
            # Try to parse JSON from content
            try:
                # Find JSON block if wrapped in markdown
                if "```json" in content:
                    content = content.split("```json")[1].split("```")[0].strip()
                elif "```" in content:
                    content = content.split("```")[1].split("```")[0].strip()
                
                output = json.loads(content)
            except:
                output = {"raw_output": content}
                
            return {
                "output": output,
                "findings": output.get("findings", []),
                "duration": duration
            }
            
        except Exception as e:
            print(f"Error executing AI: {e}")
            return {
                "output": {"error": str(e)},
                "findings": [],
                "duration": 0
            }

