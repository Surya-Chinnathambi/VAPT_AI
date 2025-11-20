"""
Semantic Search Engine
Week 7-8: Advanced search with vector similarity, hybrid search, and ranking

Combines vector search with keyword search for best results.
Supports filtering, ranking, and result aggregation.
"""
import logging
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime
import re
from core.chroma_manager import get_chroma_manager
from core.embedding_service import get_embedding_service


logger = logging.getLogger(__name__)


class SemanticSearchEngine:
    """Advanced semantic search engine"""
    
    def __init__(self):
        """Initialize search engine"""
        self.chroma = get_chroma_manager()
        self.embedding_service = get_embedding_service()
        logger.info("Semantic search engine initialized")
    
    def search_cves(
        self,
        query: str,
        filters: Optional[Dict] = None,
        top_k: int = 10,
        min_similarity: float = 0.0
    ) -> List[Dict]:
        """
        Search CVEs with semantic understanding
        
        Args:
            query: Natural language query
            filters: Optional metadata filters (severity, cvss_score, etc.)
            top_k: Number of results to return
            min_similarity: Minimum similarity threshold (0-1)
            
        Returns:
            List of CVE results with metadata and similarity scores
        """
        logger.info(f"Searching CVEs for: '{query}'")
        
        # Perform vector search
        results = self.chroma.search_cves(
            query=query,
            n_results=top_k * 2,  # Get more for filtering
            where=filters
        )
        
        # Filter by similarity threshold and format
        formatted_results = []
        for i, cve_id in enumerate(results['ids']):
            similarity = 1.0 - results['distances'][i]  # Convert distance to similarity
            
            if similarity >= min_similarity:
                formatted_results.append({
                    'cve_id': cve_id,
                    'description': results['documents'][i],
                    'metadata': results['metadatas'][i],
                    'similarity_score': float(similarity),
                    'rank': i + 1
                })
        
        # Return top-k after filtering
        return formatted_results[:top_k]
    
    def search_exploits(
        self,
        query: str,
        filters: Optional[Dict] = None,
        top_k: int = 10,
        min_similarity: float = 0.0
    ) -> List[Dict]:
        """
        Search exploits with semantic understanding
        
        Args:
            query: Natural language query
            filters: Optional metadata filters
            top_k: Number of results to return
            min_similarity: Minimum similarity threshold
            
        Returns:
            List of exploit results
        """
        logger.info(f"Searching exploits for: '{query}'")
        
        results = self.chroma.search_exploits(
            query=query,
            n_results=top_k * 2,
            where=filters
        )
        
        formatted_results = []
        for i, exploit_id in enumerate(results['ids']):
            similarity = 1.0 - results['distances'][i]
            
            if similarity >= min_similarity:
                formatted_results.append({
                    'exploit_id': exploit_id,
                    'description': results['documents'][i],
                    'metadata': results['metadatas'][i],
                    'similarity_score': float(similarity),
                    'rank': i + 1
                })
        
        return formatted_results[:top_k]
    
    def hybrid_search(
        self,
        query: str,
        search_types: List[str] = None,
        top_k_per_type: int = 5,
        aggregate: bool = True
    ) -> Dict[str, Any]:
        """
        Search across multiple data types
        
        Args:
            query: Natural language query
            search_types: List of types to search (cves, exploits, knowledge)
            top_k_per_type: Results per type
            aggregate: Whether to aggregate and rank all results
            
        Returns:
            Dictionary with results by type or aggregated list
        """
        if search_types is None:
            search_types = ['cves', 'exploits', 'knowledge']
        
        logger.info(f"Hybrid search for: '{query}' across {search_types}")
        
        results = {}
        all_results = []
        
        # Search CVEs
        if 'cves' in search_types:
            cve_results = self.search_cves(query, top_k=top_k_per_type)
            results['cves'] = cve_results
            
            for r in cve_results:
                r['source'] = 'cve'
                all_results.append(r)
        
        # Search exploits
        if 'exploits' in search_types:
            exploit_results = self.search_exploits(query, top_k=top_k_per_type)
            results['exploits'] = exploit_results
            
            for r in exploit_results:
                r['source'] = 'exploit'
                all_results.append(r)
        
        # Search knowledge base
        if 'knowledge' in search_types:
            knowledge_results = self.search_knowledge(query, top_k=top_k_per_type)
            results['knowledge'] = knowledge_results
            
            for r in knowledge_results:
                r['source'] = 'knowledge'
                all_results.append(r)
        
        if aggregate:
            # Sort all results by similarity score
            all_results.sort(key=lambda x: x['similarity_score'], reverse=True)
            
            return {
                'query': query,
                'total_results': len(all_results),
                'results': all_results,
                'results_by_type': results
            }
        else:
            return {
                'query': query,
                'results_by_type': results
            }
    
    def search_knowledge(
        self,
        query: str,
        filters: Optional[Dict] = None,
        top_k: int = 5,
        min_similarity: float = 0.0
    ) -> List[Dict]:
        """
        Search security knowledge base
        
        Args:
            query: Natural language query
            filters: Optional metadata filters
            top_k: Number of results
            min_similarity: Minimum similarity threshold
            
        Returns:
            List of knowledge results
        """
        results = self.chroma.search_security_knowledge(
            query=query,
            n_results=top_k * 2,
            where=filters
        )
        
        formatted_results = []
        for i, doc_id in enumerate(results['ids']):
            similarity = 1.0 - results['distances'][i]
            
            if similarity >= min_similarity:
                formatted_results.append({
                    'doc_id': doc_id,
                    'content': results['documents'][i],
                    'metadata': results['metadatas'][i],
                    'similarity_score': float(similarity),
                    'rank': i + 1
                })
        
        return formatted_results[:top_k]
    
    def find_related_cves(
        self,
        cve_id: str,
        top_k: int = 5
    ) -> List[Dict]:
        """
        Find CVEs related to a specific CVE
        
        Args:
            cve_id: CVE ID to find related CVEs for
            top_k: Number of related CVEs to return
            
        Returns:
            List of related CVEs
        """
        logger.info(f"Finding related CVEs for {cve_id}")
        
        # Get the original CVE
        try:
            collection = self.chroma.get_or_create_collection(self.chroma.CVE_COLLECTION)
            original = collection.get(ids=[cve_id])
            
            if not original['documents']:
                logger.warning(f"CVE {cve_id} not found")
                return []
            
            # Use original CVE description as query
            query = original['documents'][0]
            
            # Search for similar CVEs
            results = self.search_cves(query, top_k=top_k + 1)
            
            # Filter out the original CVE
            related = [r for r in results if r['cve_id'] != cve_id]
            
            return related[:top_k]
            
        except Exception as e:
            logger.error(f"Failed to find related CVEs: {e}")
            return []
    
    def find_exploits_for_cve(
        self,
        cve_id: str,
        top_k: int = 5
    ) -> List[Dict]:
        """
        Find exploits related to a CVE
        
        Args:
            cve_id: CVE ID
            top_k: Number of exploits to return
            
        Returns:
            List of related exploits
        """
        logger.info(f"Finding exploits for {cve_id}")
        
        # Extract CVE year and number for search
        query = f"{cve_id} exploit proof-of-concept"
        
        # Search exploits with CVE ID in metadata or description
        results = self.search_exploits(query, top_k=top_k)
        
        return results
    
    def search_with_context(
        self,
        query: str,
        context: Optional[Dict] = None,
        top_k: int = 10
    ) -> Dict[str, Any]:
        """
        Search with additional context (e.g., previous scan results)
        
        Args:
            query: Natural language query
            context: Additional context (scan results, target info, etc.)
            top_k: Number of results
            
        Returns:
            Enhanced search results with context
        """
        # Enhance query with context
        enhanced_query = query
        
        if context:
            if context.get('target_host'):
                enhanced_query += f" affecting {context['target_host']}"
            
            if context.get('open_ports'):
                ports_str = ','.join(str(p) for p in context['open_ports'][:5])
                enhanced_query += f" on ports {ports_str}"
            
            if context.get('detected_services'):
                services = ','.join(context['detected_services'][:3])
                enhanced_query += f" related to {services}"
        
        logger.info(f"Contextual search: '{enhanced_query}'")
        
        # Perform hybrid search
        results = self.hybrid_search(
            query=enhanced_query,
            top_k_per_type=top_k,
            aggregate=True
        )
        
        # Add context to results
        results['context'] = context
        results['original_query'] = query
        results['enhanced_query'] = enhanced_query
        
        return results
    
    def rank_results(
        self,
        results: List[Dict],
        ranking_weights: Optional[Dict[str, float]] = None
    ) -> List[Dict]:
        """
        Re-rank results using custom weights
        
        Args:
            results: List of search results
            ranking_weights: Weights for ranking factors
            
        Returns:
            Re-ranked results
        """
        if ranking_weights is None:
            ranking_weights = {
                'similarity_score': 0.6,
                'severity': 0.3,
                'recency': 0.1
            }
        
        scored_results = []
        
        for result in results:
            score = 0.0
            
            # Similarity score
            if 'similarity_score' in result:
                score += result['similarity_score'] * ranking_weights.get('similarity_score', 0.6)
            
            # Severity (for CVEs)
            if 'metadata' in result:
                metadata = result['metadata']
                
                if 'severity' in metadata:
                    severity_scores = {
                        'CRITICAL': 1.0,
                        'HIGH': 0.8,
                        'MEDIUM': 0.5,
                        'LOW': 0.2
                    }
                    severity_score = severity_scores.get(metadata['severity'], 0.0)
                    score += severity_score * ranking_weights.get('severity', 0.3)
                
                # Recency (newer CVEs weighted higher)
                if 'published_date' in metadata:
                    try:
                        pub_date = datetime.fromisoformat(metadata['published_date'])
                        days_old = (datetime.now() - pub_date).days
                        recency_score = max(0.0, 1.0 - (days_old / 365.0))  # Decay over 1 year
                        score += recency_score * ranking_weights.get('recency', 0.1)
                    except:
                        pass
            
            result['final_score'] = score
            scored_results.append(result)
        
        # Sort by final score
        scored_results.sort(key=lambda x: x['final_score'], reverse=True)
        
        # Update ranks
        for i, result in enumerate(scored_results):
            result['rank'] = i + 1
        
        return scored_results


# Global singleton
_search_engine: Optional[SemanticSearchEngine] = None


def get_search_engine() -> SemanticSearchEngine:
    """Get or create search engine singleton"""
    global _search_engine
    if _search_engine is None:
        _search_engine = SemanticSearchEngine()
    return _search_engine
