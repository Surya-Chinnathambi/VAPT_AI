"""
Vector Search API Router
Week 7-8: REST API endpoints for semantic search and AI agents

Endpoints:
- POST /api/vector-search/semantic: Semantic search across all collections
- POST /api/vector-search/cves: CVE-specific search
- POST /api/vector-search/exploits: Exploit-specific search  
- POST /api/vector-search/hybrid: Hybrid search with filters
- POST /api/agents/analyze-cve: Multi-agent CVE analysis
- POST /api/agents/find-exploits: Exploit research
- POST /api/agents/get-recommendations: Security recommendations
"""
import logging
from typing import List, Dict, Optional, Any
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Optional chromadb imports - gracefully handle if not installed
try:
    from core.semantic_search import get_search_engine
    from core.ai_agents import (
        get_cve_agent,
        get_exploit_agent,
        get_recommendation_agent,
        get_coordinator
    )
    from workers.indexing_tasks import (
        index_cves_task,
        index_exploits_task,
        index_security_knowledge_task
    )
    CHROMADB_AVAILABLE = True
except ImportError as e:
    logger.warning(f"ChromaDB features not available: {e}")
    CHROMADB_AVAILABLE = False

from routers.auth import get_current_user


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/vector-search", tags=["Vector Search"])
agents_router = APIRouter(prefix="/api/agents", tags=["AI Agents"])


# Request models

class SemanticSearchRequest(BaseModel):
    """Semantic search request"""
    query: str = Field(..., min_length=1, max_length=500, description="Search query")
    top_k: int = Field(10, ge=1, le=50, description="Number of results")
    min_similarity: float = Field(0.0, ge=0.0, le=1.0, description="Minimum similarity threshold")
    search_types: Optional[List[str]] = Field(None, description="Types to search: cves, exploits, knowledge")


class CVESearchRequest(BaseModel):
    """CVE search request"""
    query: str = Field(..., min_length=1, max_length=500)
    filters: Optional[Dict[str, Any]] = Field(None, description="Metadata filters")
    top_k: int = Field(10, ge=1, le=50)
    min_similarity: float = Field(0.0, ge=0.0, le=1.0)


class ExploitSearchRequest(BaseModel):
    """Exploit search request"""
    query: str = Field(..., min_length=1, max_length=500)
    filters: Optional[Dict[str, Any]] = None
    top_k: int = Field(10, ge=1, le=50)
    min_similarity: float = Field(0.0, ge=0.0, le=1.0)


class HybridSearchRequest(BaseModel):
    """Hybrid search request"""
    query: str = Field(..., min_length=1, max_length=500)
    search_types: List[str] = Field(["cves", "exploits"], description="Types to search")
    top_k_per_type: int = Field(5, ge=1, le=20)
    aggregate: bool = Field(True, description="Aggregate results from all types")


class CVEAnalysisRequest(BaseModel):
    """CVE analysis request"""
    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,}$", description="CVE identifier")
    comprehensive: bool = Field(False, description="Use all agents for comprehensive analysis")


class ExploitResearchRequest(BaseModel):
    """Exploit research request"""
    cve_id: Optional[str] = Field(None, pattern=r"^CVE-\d{4}-\d{4,}$")
    vulnerability_description: Optional[str] = Field(None, max_length=1000)


class RecommendationRequest(BaseModel):
    """Recommendation request"""
    cve_ids: List[str] = Field(..., min_items=1, max_items=10)
    prioritize: bool = Field(True, description="Prioritize vulnerabilities")


class IndexRequest(BaseModel):
    """Index request"""
    cve_ids: Optional[List[str]] = None
    exploit_ids: Optional[List[str]] = None
    force_reindex: bool = False


# Vector Search Endpoints

@router.post("/semantic")
async def semantic_search(
    request: SemanticSearchRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Perform semantic search across all collections
    
    Returns relevant CVEs, exploits, and knowledge base entries
    """
    if not CHROMADB_AVAILABLE:
        raise HTTPException(
            status_code=501,
            detail="Vector search features are not available. ChromaDB is not installed."
        )
    
    try:
        logger.info(f"Semantic search: '{request.query}' by user {current_user['email']}")
        
        search_engine = get_search_engine()
        
        results = search_engine.hybrid_search(
            query=request.query,
            search_types=request.search_types or ['cves', 'exploits', 'knowledge'],
            top_k_per_type=request.top_k,
            aggregate=True
        )
        
        return {
            "status": "success",
            "query": request.query,
            "results": results
        }
        
    except Exception as e:
        logger.error(f"Semantic search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cves")
async def search_cves(
    request: CVESearchRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Search CVE database with semantic understanding
    
    Returns relevant CVE entries with similarity scores
    """
    try:
        logger.info(f"CVE search: '{request.query}' by user {current_user['email']}")
        
        search_engine = get_search_engine()
        
        results = search_engine.search_cves(
            query=request.query,
            filters=request.filters,
            top_k=request.top_k,
            min_similarity=request.min_similarity
        )
        
        return {
            "status": "success",
            "query": request.query,
            "total_results": len(results),
            "results": results
        }
        
    except Exception as e:
        logger.error(f"CVE search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/exploits")
async def search_exploits(
    request: ExploitSearchRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Search exploit database with semantic understanding
    
    Returns relevant exploit entries with similarity scores
    """
    try:
        logger.info(f"Exploit search: '{request.query}' by user {current_user['email']}")
        
        search_engine = get_search_engine()
        
        results = search_engine.search_exploits(
            query=request.query,
            filters=request.filters,
            top_k=request.top_k,
            min_similarity=request.min_similarity
        )
        
        return {
            "status": "success",
            "query": request.query,
            "total_results": len(results),
            "results": results
        }
        
    except Exception as e:
        logger.error(f"Exploit search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/hybrid")
async def hybrid_search(
    request: HybridSearchRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Hybrid search across multiple data types
    
    Combines vector similarity with metadata filtering
    """
    try:
        logger.info(f"Hybrid search: '{request.query}' by user {current_user['email']}")
        
        search_engine = get_search_engine()
        
        results = search_engine.hybrid_search(
            query=request.query,
            search_types=request.search_types,
            top_k_per_type=request.top_k_per_type,
            aggregate=request.aggregate
        )
        
        return {
            "status": "success",
            "query": request.query,
            "results": results
        }
        
    except Exception as e:
        logger.error(f"Hybrid search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/related-cves/{cve_id}")
async def find_related_cves(
    cve_id: str,
    top_k: int = 5,
    current_user: dict = Depends(get_current_user)
):
    """
    Find CVEs related to a specific CVE
    
    Uses semantic similarity to find related vulnerabilities
    """
    try:
        logger.info(f"Finding related CVEs for {cve_id}")
        
        search_engine = get_search_engine()
        
        results = search_engine.find_related_cves(cve_id, top_k=top_k)
        
        return {
            "status": "success",
            "cve_id": cve_id,
            "related_cves": results
        }
        
    except Exception as e:
        logger.error(f"Related CVE search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/exploits-for-cve/{cve_id}")
async def find_exploits_for_cve(
    cve_id: str,
    top_k: int = 5,
    current_user: dict = Depends(get_current_user)
):
    """
    Find exploits related to a CVE
    
    Searches for proof-of-concept exploits and attack techniques
    """
    try:
        logger.info(f"Finding exploits for {cve_id}")
        
        search_engine = get_search_engine()
        
        results = search_engine.find_exploits_for_cve(cve_id, top_k=top_k)
        
        return {
            "status": "success",
            "cve_id": cve_id,
            "exploits": results
        }
        
    except Exception as e:
        logger.error(f"Exploit search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# AI Agent Endpoints

@agents_router.post("/analyze-cve")
async def analyze_cve(
    request: CVEAnalysisRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Analyze a CVE using AI agents
    
    Provides detailed analysis, severity assessment, and impact
    """
    try:
        logger.info(f"AI CVE analysis for {request.cve_id}")
        
        if request.comprehensive:
            # Use coordinator for comprehensive analysis
            coordinator = get_coordinator()
            results = coordinator.comprehensive_analysis(request.cve_id)
        else:
            # Use only CVE agent
            cve_agent = get_cve_agent()
            results = cve_agent.analyze_cve(request.cve_id)
        
        return {
            "status": "success",
            "cve_id": request.cve_id,
            "analysis": results
        }
        
    except Exception as e:
        logger.error(f"CVE analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@agents_router.post("/find-exploits")
async def research_exploits(
    request: ExploitResearchRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Research exploits using AI agent
    
    Finds available exploits and assesses exploitability
    """
    try:
        logger.info("AI exploit research")
        
        exploit_agent = get_exploit_agent()
        
        if request.cve_id:
            results = exploit_agent.find_exploits_for_cve(request.cve_id)
        elif request.vulnerability_description:
            results = exploit_agent.assess_exploitability(request.vulnerability_description)
        else:
            raise HTTPException(
                status_code=400,
                detail="Either cve_id or vulnerability_description required"
            )
        
        return {
            "status": "success",
            "research": results
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Exploit research failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@agents_router.post("/get-recommendations")
async def get_recommendations(
    request: RecommendationRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Get security recommendations using AI agent
    
    Provides mitigation strategies and prioritization
    """
    try:
        logger.info(f"AI recommendations for {len(request.cve_ids)} CVEs")
        
        recommendation_agent = get_recommendation_agent()
        
        if request.prioritize and len(request.cve_ids) > 1:
            results = recommendation_agent.prioritize_vulnerabilities(request.cve_ids)
        else:
            # Get mitigation for single CVE
            results = recommendation_agent.get_mitigation_advice(request.cve_ids[0])
        
        return {
            "status": "success",
            "recommendations": results
        }
        
    except Exception as e:
        logger.error(f"Recommendation generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Indexing Endpoints

@router.post("/index/cves")
async def trigger_cve_indexing(
    request: IndexRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """
    Trigger background indexing of CVEs
    
    Requires admin privileges
    """
    if not current_user.get('is_admin'):
        raise HTTPException(status_code=403, detail="Admin privileges required")
    
    try:
        # Trigger background task
        task = index_cves_task.delay(
            cve_ids=request.cve_ids,
            force_reindex=request.force_reindex
        )
        
        return {
            "status": "success",
            "message": "CVE indexing started",
            "task_id": task.id
        }
        
    except Exception as e:
        logger.error(f"Failed to start CVE indexing: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/index/exploits")
async def trigger_exploit_indexing(
    request: IndexRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """
    Trigger background indexing of exploits
    
    Requires admin privileges
    """
    if not current_user.get('is_admin'):
        raise HTTPException(status_code=403, detail="Admin privileges required")
    
    try:
        task = index_exploits_task.delay(
            exploit_ids=request.exploit_ids,
            force_reindex=request.force_reindex
        )
        
        return {
            "status": "success",
            "message": "Exploit indexing started",
            "task_id": task.id
        }
        
    except Exception as e:
        logger.error(f"Failed to start exploit indexing: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/index/knowledge")
async def trigger_knowledge_indexing(
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """
    Trigger background indexing of security knowledge
    
    Requires admin privileges
    """
    if not current_user.get('is_admin'):
        raise HTTPException(status_code=403, detail="Admin privileges required")
    
    try:
        task = index_security_knowledge_task.delay()
        
        return {
            "status": "success",
            "message": "Knowledge base indexing started",
            "task_id": task.id
        }
        
    except Exception as e:
        logger.error(f"Failed to start knowledge indexing: {e}")
        raise HTTPException(status_code=500, detail=str(e))
