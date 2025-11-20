import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime

class AIVAPTPerformanceTracker:
    def __init__(self):
        self.metrics = {
            "current_level": "basic",  # basic, medium, expert
            "scenarios_completed": 0,
            "success_rate": 0.0,
            "false_positive_rate": 0.0,
            "time_efficiency": 0.0,
            "manual_task_reduction": 0.0,  # % of manual work eliminated
            "learning_curve": []  # Track improvement over time
        }
        
        self.advancement_criteria = {
            "basic_to_medium": {
                "scenarios_completed": 50,
                "success_rate": 0.85,
                "false_positive_rate": 0.10,
                "time_efficiency": 0.90,
                "human_approval_rate": 0.95
            },
            "medium_to_expert": {
                "scenarios_completed": 100,
                "success_rate": 0.90,
                "false_positive_rate": 0.05,
                "exploitation_success": 0.80,
                "prioritization_accuracy": 0.85,
                "autonomous_decision_quality": 0.90
            },
            "expert_certification": {
                "scenarios_completed": 200,
                "success_rate": 0.95,
                "false_positive_rate": 0.03,
                "attack_chain_success": 0.90,
                "business_logic_detection": 0.70,
                "autonomous_operation": 0.85,
                "report_quality": 0.95
            }
        }
    
    async def evaluate_scenario(self, scenario_id, result, scenario):
        """Evaluate AI performance on a scenario"""
        
        # Compare AI output vs expected output
        accuracy = self.calculate_accuracy(result.get('output'), scenario.get('expected_output'))
        
        # Check for false positives
        false_positives = self.detect_false_positives(result.get('findings', []))
        
        # Measure time efficiency
        # Assuming duration is in minutes for simplicity
        expected_duration_str = scenario.get('expected_duration', "5 minutes")
        try:
            expected_duration = int(expected_duration_str.split('-')[0].strip().split(' ')[0])
        except:
            expected_duration = 5
            
        time_ratio = result.get('duration', expected_duration) / expected_duration
        
        # Update metrics
        self.metrics["success_rate"] = self.update_rolling_average(self.metrics["success_rate"], accuracy)
        self.metrics["false_positive_rate"] = self.update_rolling_average(self.metrics["false_positive_rate"], false_positives)
        self.metrics["time_efficiency"] = self.update_rolling_average(self.metrics["time_efficiency"], time_ratio)
        self.metrics["scenarios_completed"] += 1
        
        # Check if ready for level advancement
        if self.check_advancement_criteria():
            return {"advance": True, "next_level": self.get_next_level()}
        
        return {"advance": False, "improvement_needed": self.suggest_improvements()}

    def calculate_accuracy(self, output, expected_output):
        # Placeholder for accuracy calculation logic
        return 0.9

    def detect_false_positives(self, findings):
        # Placeholder for false positive detection
        return 0.05

    def update_rolling_average(self, current, new_val, window=10):
        # Simple moving average approximation
        return (current * (window - 1) + new_val) / window

    def check_advancement_criteria(self):
        current_level = self.metrics["current_level"]
        if current_level == "basic":
            criteria = self.advancement_criteria["basic_to_medium"]
            return (self.metrics["scenarios_completed"] >= criteria["scenarios_completed"] and
                    self.metrics["success_rate"] >= criteria["success_rate"])
        elif current_level == "medium":
            criteria = self.advancement_criteria["medium_to_expert"]
            return (self.metrics["scenarios_completed"] >= criteria["scenarios_completed"] and
                    self.metrics["success_rate"] >= criteria["success_rate"])
        return False

    def get_next_level(self):
        if self.metrics["current_level"] == "basic":
            return "medium"
        elif self.metrics["current_level"] == "medium":
            return "expert"
        return "expert"

    def suggest_improvements(self):
        return "Continue training on current level scenarios."
    
    # Additional methods for enhanced training manager
    
    def record_scenario_result(self, scenario_id: str, score: float):
        """Record result of a scenario execution"""
        if not hasattr(self, 'scenario_results'):
            self.scenario_results = {}
        
        self.scenario_results[scenario_id] = {
            "score": score,
            "timestamp": datetime.now().isoformat()
        }
        
        # Update metrics
        self.metrics["scenarios_completed"] += 1
        self.metrics["success_rate"] = self.update_rolling_average(
            self.metrics["success_rate"],
            score
        )
    
    def get_level_metrics(self, level: str) -> Optional[Dict[str, Any]]:
        """Get performance metrics for a specific level"""
        level_map = {
            "level1": "basic",
            "level2": "medium",
            "level3": "expert"
        }
        
        mapped_level = level_map.get(level, level)
        
        if not hasattr(self, 'scenario_results'):
            return None
        
        # Filter results by level (assuming scenario IDs start with level prefix)
        level_prefix = level.replace("level", "L")
        level_results = {
            k: v for k, v in self.scenario_results.items()
            if k.startswith(level_prefix)
        }
        
        if not level_results:
            return None
        
        scores = [r["score"] for r in level_results.values()]
        avg_score = sum(scores) / len(scores)
        success_rate = sum(1 for s in scores if s >= 0.85) / len(scores)
        
        return {
            "total_scenarios": len(level_results),
            "average_score": avg_score,
            "success_rate": success_rate,
            "ready_for_advancement": avg_score >= 0.85 and success_rate >= 0.85
        }
    
    def get_current_level(self) -> str:
        """Get current training level"""
        return self.metrics["current_level"]
    
    def can_advance(self) -> bool:
        """Check if ready to advance to next level"""
        return self.check_advancement_criteria()
    
    def reset(self):
        """Reset all performance tracking"""
        self.__init__()


# Singleton instance
_performance_tracker = None


def get_performance_tracker() -> AIVAPTPerformanceTracker:
    """Get singleton PerformanceTracker instance"""
    global _performance_tracker
    if _performance_tracker is None:
        _performance_tracker = AIVAPTPerformanceTracker()
    return _performance_tracker
