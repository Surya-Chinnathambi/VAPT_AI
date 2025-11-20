"""
AI VAPT Training API Router
Exposes endpoints for AI training scenarios, tool execution, and performance tracking
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging

from backend.ai_training.enhanced_training import get_enhanced_training_manager
from backend.ai_training.performance_tracker import get_performance_tracker

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ai-training", tags=["AI Training"])


# Pydantic Models

class ScenarioExecutionRequest(BaseModel):
    scenario_id: str = Field(..., description="Scenario ID to execute")
    level: str = Field(..., description="Training level (level1, level2, level3)")


class TrainingBatchRequest(BaseModel):
    level: str = Field(..., description="Training level")
    num_scenarios: int = Field(10, ge=1, le=50, description="Number of scenarios to run")
    scenario_filter: Optional[Dict[str, Any]] = Field(None, description="Filter criteria")


class ScenarioListRequest(BaseModel):
    level: Optional[str] = Field(None, description="Filter by level")
    difficulty: Optional[str] = Field(None, description="Filter by difficulty")
    limit: int = Field(50, ge=1, le=200, description="Max scenarios to return")


# API Endpoints

@router.get("/scenarios")
async def list_scenarios(
    level: Optional[str] = None,
    difficulty: Optional[str] = None,
    limit: int = 50
):
    """
    List available training scenarios
    
    Query Parameters:
    - level: Filter by level (level1, level2, level3)
    - difficulty: Filter by difficulty (easy, medium, hard, expert)
    - limit: Maximum scenarios to return
    
    Returns:
    - List of scenarios with metadata
    """
    
    try:
        manager = get_enhanced_training_manager()
        
        # Get all scenarios
        all_scenarios = []
        for lvl in ["level1", "level2", "level3"]:
            if level and lvl != level:
                continue
            
            scenarios = manager.all_scenarios.get(lvl, [])
            for scenario in scenarios:
                scenario_meta = {
                    **scenario,
                    "level": lvl
                }
                
                # Apply difficulty filter
                if difficulty and scenario.get('difficulty') != difficulty:
                    continue
                
                all_scenarios.append(scenario_meta)
        
        # Limit results
        all_scenarios = all_scenarios[:limit]
        
        return {
            "total": len(all_scenarios),
            "scenarios": all_scenarios
        }
    
    except Exception as e:
        logger.error(f"Failed to list scenarios: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/execute-scenario")
async def execute_scenario(request: ScenarioExecutionRequest):
    """
    Execute a specific training scenario
    
    Body:
    - scenario_id: Scenario to execute
    - level: Training level
    
    Returns:
    - Execution results including AI plan, tool results, and performance metrics
    """
    
    try:
        manager = get_enhanced_training_manager()
        
        # Find scenario
        scenarios = manager.all_scenarios.get(request.level, [])
        scenario = next(
            (s for s in scenarios if s['scenario_id'] == request.scenario_id),
            None
        )
        
        if not scenario:
            raise HTTPException(
                status_code=404,
                detail=f"Scenario {request.scenario_id} not found in {request.level}"
            )
        
        # Execute scenario
        result = await manager.execute_scenario_with_tools(scenario, request.level)
        
        return {
            "scenario_id": request.scenario_id,
            "level": request.level,
            "executed_at": datetime.now().isoformat(),
            "result": result
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Scenario execution failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/run-batch")
async def run_training_batch(request: TrainingBatchRequest, background_tasks: BackgroundTasks):
    """
    Run a batch of training scenarios
    
    Body:
    - level: Training level
    - num_scenarios: Number to run
    - scenario_filter: Optional filter criteria
    
    Returns:
    - Batch execution summary
    """
    
    try:
        manager = get_enhanced_training_manager()
        
        # Execute batch
        result = await manager.run_training_batch(
            level=request.level,
            num_scenarios=request.num_scenarios,
            scenario_filter=request.scenario_filter
        )
        
        return {
            "batch_id": f"{request.level}_{datetime.now().timestamp()}",
            "started_at": datetime.now().isoformat(),
            "result": result
        }
    
    except Exception as e:
        logger.error(f"Batch execution failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/performance/{level}")
async def get_performance_stats(level: str):
    """
    Get performance statistics for a training level
    
    Path Parameters:
    - level: Training level (level1, level2, level3)
    
    Returns:
    - Performance metrics and readiness for advancement
    """
    
    try:
        tracker = get_performance_tracker()
        
        # Get performance metrics
        metrics = tracker.get_level_metrics(level)
        
        if not metrics:
            return {
                "level": level,
                "total_scenarios": 0,
                "average_score": 0.0,
                "success_rate": 0.0,
                "ready_for_advancement": False
            }
        
        return {
            "level": level,
            **metrics
        }
    
    except Exception as e:
        logger.error(f"Failed to get performance stats: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/advancement-status")
async def check_advancement_status():
    """
    Check if AI is ready to advance to next level
    
    Returns:
    - Current level, metrics, and advancement readiness
    """
    
    try:
        tracker = get_performance_tracker()
        
        # Check all levels
        status = {
            "level1": tracker.get_level_metrics("level1"),
            "level2": tracker.get_level_metrics("level2"),
            "level3": tracker.get_level_metrics("level3"),
            "current_level": tracker.get_current_level(),
            "can_advance": tracker.can_advance()
        }
        
        return status
    
    except Exception as e:
        logger.error(f"Failed to check advancement status: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tools/status")
async def get_tool_status():
    """
    Get status of all security testing tools
    
    Returns:
    - Tool availability and health status
    """
    
    try:
        from backend.ai_training.tool_executor import get_tool_executor
        
        executor = get_tool_executor()
        
        # Check tool availability
        tools = [
            "nmap", "nuclei", "nikto", "testssl",
            "sqlmap", "sublist3r", "amass", "whois", "dig"
        ]
        
        tool_status = {}
        for tool in tools:
            # Simple availability check (could be enhanced with actual health checks)
            tool_status[tool] = {
                "available": True,  # Assume available if in container
                "rate_limit": executor.rate_limiter.call_history.get(tool, [])
            }
        
        return {
            "tools": tool_status,
            "total_tools": len(tools),
            "all_available": all(t.get("available") for t in tool_status.values())
        }
    
    except Exception as e:
        logger.error(f"Failed to get tool status: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/reset-performance")
async def reset_performance_tracking():
    """
    Reset performance tracking (for testing/debugging)
    
    Returns:
    - Confirmation message
    """
    
    try:
        tracker = get_performance_tracker()
        tracker.reset()
        
        return {
            "status": "success",
            "message": "Performance tracking reset successfully"
        }
    
    except Exception as e:
        logger.error(f"Failed to reset performance tracking: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats/overview")
async def get_training_overview():
    """
    Get comprehensive training overview
    
    Returns:
    - Overall training statistics, scenario counts, performance metrics
    """
    
    try:
        manager = get_enhanced_training_manager()
        tracker = get_performance_tracker()
        
        # Count scenarios by level
        scenario_counts = {
            "level1": len(manager.all_scenarios.get("level1", [])),
            "level2": len(manager.all_scenarios.get("level2", [])),
            "level3": len(manager.all_scenarios.get("level3", []))
        }
        
        # Get performance metrics
        performance = {
            "level1": tracker.get_level_metrics("level1"),
            "level2": tracker.get_level_metrics("level2"),
            "level3": tracker.get_level_metrics("level3")
        }
        
        return {
            "total_scenarios": sum(scenario_counts.values()),
            "scenario_counts": scenario_counts,
            "performance": performance,
            "current_level": tracker.get_current_level(),
            "can_advance": tracker.can_advance(),
            "training_active": True
        }
    
    except Exception as e:
        logger.error(f"Failed to get training overview: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
