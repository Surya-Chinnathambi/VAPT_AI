"""
Embedding Service for Vector Search
Week 7-8: Generate embeddings for CVEs, exploits, and security content

Uses sentence-transformers for high-quality semantic embeddings.
Supports batching, caching, and multiple embedding models.
"""
import os
import logging
from typing import List, Dict, Optional, Union
from functools import lru_cache
import hashlib
import numpy as np
from sentence_transformers import SentenceTransformer


logger = logging.getLogger(__name__)


class EmbeddingService:
    """Service for generating text embeddings"""
    
    # Available models (ordered by quality/speed tradeoff)
    MODELS = {
        "fast": "all-MiniLM-L6-v2",        # 384 dim, very fast
        "balanced": "all-mpnet-base-v2",   # 768 dim, good balance
        "quality": "all-MiniLM-L12-v2",    # 384 dim, higher quality
    }
    
    def __init__(self, model_name: Optional[str] = None):
        """
        Initialize embedding service
        
        Args:
            model_name: Model to use (fast, balanced, quality) or full model name
        """
        if model_name is None:
            model_name = os.getenv("EMBEDDING_MODEL", "fast")
        
        # Resolve model name
        if model_name in self.MODELS:
            self.model_id = self.MODELS[model_name]
            self.model_type = model_name
        else:
            self.model_id = model_name
            self.model_type = "custom"
        
        # Load model
        logger.info(f"Loading embedding model: {self.model_id}")
        self.model = SentenceTransformer(self.model_id)
        self.dimension = self.model.get_sentence_embedding_dimension()
        
        logger.info(f"Embedding model loaded: {self.model_id} (dim={self.dimension})")
    
    def generate_embedding(self, text: str) -> np.ndarray:
        """
        Generate embedding for single text
        
        Args:
            text: Input text
            
        Returns:
            Numpy array of embeddings
        """
        if not text or not text.strip():
            logger.warning("Empty text provided for embedding")
            return np.zeros(self.dimension)
        
        try:
            embedding = self.model.encode(
                text,
                convert_to_numpy=True,
                show_progress_bar=False
            )
            return embedding
        except Exception as e:
            logger.error(f"Failed to generate embedding: {e}")
            return np.zeros(self.dimension)
    
    def generate_embeddings_batch(
        self,
        texts: List[str],
        batch_size: int = 32,
        show_progress: bool = False
    ) -> np.ndarray:
        """
        Generate embeddings for batch of texts
        
        Args:
            texts: List of input texts
            batch_size: Batch size for encoding
            show_progress: Show progress bar
            
        Returns:
            Numpy array of embeddings (n_texts, dimension)
        """
        if not texts:
            logger.warning("Empty text list provided for batch embedding")
            return np.zeros((0, self.dimension))
        
        try:
            embeddings = self.model.encode(
                texts,
                batch_size=batch_size,
                convert_to_numpy=True,
                show_progress_bar=show_progress
            )
            return embeddings
        except Exception as e:
            logger.error(f"Failed to generate batch embeddings: {e}")
            return np.zeros((len(texts), self.dimension))
    
    @lru_cache(maxsize=1000)
    def generate_embedding_cached(self, text: str) -> tuple:
        """
        Generate embedding with caching (for frequently used texts)
        
        Args:
            text: Input text
            
        Returns:
            Tuple of embedding values (hashable for caching)
        """
        embedding = self.generate_embedding(text)
        return tuple(embedding.tolist())
    
    def compute_similarity(
        self,
        embedding1: Union[np.ndarray, List[float]],
        embedding2: Union[np.ndarray, List[float]]
    ) -> float:
        """
        Compute cosine similarity between two embeddings
        
        Args:
            embedding1: First embedding
            embedding2: Second embedding
            
        Returns:
            Similarity score (0-1, higher is more similar)
        """
        if isinstance(embedding1, list):
            embedding1 = np.array(embedding1)
        if isinstance(embedding2, list):
            embedding2 = np.array(embedding2)
        
        # Cosine similarity
        similarity = np.dot(embedding1, embedding2) / (
            np.linalg.norm(embedding1) * np.linalg.norm(embedding2)
        )
        return float(similarity)
    
    def find_most_similar(
        self,
        query_embedding: Union[np.ndarray, List[float]],
        candidate_embeddings: np.ndarray,
        top_k: int = 5
    ) -> List[tuple]:
        """
        Find most similar embeddings from candidates
        
        Args:
            query_embedding: Query embedding
            candidate_embeddings: Array of candidate embeddings (n_candidates, dim)
            top_k: Number of top results to return
            
        Returns:
            List of (index, similarity_score) tuples
        """
        if isinstance(query_embedding, list):
            query_embedding = np.array(query_embedding)
        
        # Compute similarities
        similarities = np.dot(candidate_embeddings, query_embedding) / (
            np.linalg.norm(candidate_embeddings, axis=1) * np.linalg.norm(query_embedding)
        )
        
        # Get top-k indices
        top_indices = np.argsort(similarities)[::-1][:top_k]
        
        # Return (index, score) pairs
        results = [(int(idx), float(similarities[idx])) for idx in top_indices]
        return results
    
    def get_model_info(self) -> Dict:
        """Get information about loaded model"""
        return {
            "model_id": self.model_id,
            "model_type": self.model_type,
            "dimension": self.dimension,
            "max_sequence_length": self.model.max_seq_length
        }


class CVEEmbeddingGenerator:
    """Specialized embedding generator for CVE data"""
    
    def __init__(self, embedding_service: Optional[EmbeddingService] = None):
        """
        Initialize CVE embedding generator
        
        Args:
            embedding_service: Optional existing embedding service
        """
        self.embedding_service = embedding_service or EmbeddingService()
    
    def generate_cve_embedding(self, cve_data: Dict) -> np.ndarray:
        """
        Generate embedding for CVE entry
        
        Args:
            cve_data: Dictionary with CVE information
            
        Returns:
            Embedding vector
        """
        # Construct comprehensive text from CVE data
        text_parts = []
        
        if cve_data.get('id'):
            text_parts.append(f"CVE ID: {cve_data['id']}")
        
        if cve_data.get('description'):
            text_parts.append(f"Description: {cve_data['description']}")
        
        if cve_data.get('severity'):
            text_parts.append(f"Severity: {cve_data['severity']}")
        
        if cve_data.get('cvss_score'):
            text_parts.append(f"CVSS Score: {cve_data['cvss_score']}")
        
        if cve_data.get('affected_products'):
            products = ', '.join(cve_data['affected_products'])
            text_parts.append(f"Affected: {products}")
        
        if cve_data.get('vulnerability_type'):
            text_parts.append(f"Type: {cve_data['vulnerability_type']}")
        
        combined_text = ". ".join(text_parts)
        return self.embedding_service.generate_embedding(combined_text)
    
    def generate_cve_embeddings_batch(
        self,
        cve_data_list: List[Dict],
        show_progress: bool = True
    ) -> np.ndarray:
        """
        Generate embeddings for batch of CVEs
        
        Args:
            cve_data_list: List of CVE dictionaries
            show_progress: Show progress bar
            
        Returns:
            Array of embeddings
        """
        texts = []
        for cve_data in cve_data_list:
            text_parts = []
            
            if cve_data.get('id'):
                text_parts.append(f"CVE ID: {cve_data['id']}")
            
            if cve_data.get('description'):
                text_parts.append(f"Description: {cve_data['description']}")
            
            if cve_data.get('severity'):
                text_parts.append(f"Severity: {cve_data['severity']}")
            
            combined_text = ". ".join(text_parts)
            texts.append(combined_text)
        
        return self.embedding_service.generate_embeddings_batch(
            texts,
            show_progress=show_progress
        )


class ExploitEmbeddingGenerator:
    """Specialized embedding generator for exploit data"""
    
    def __init__(self, embedding_service: Optional[EmbeddingService] = None):
        """
        Initialize exploit embedding generator
        
        Args:
            embedding_service: Optional existing embedding service
        """
        self.embedding_service = embedding_service or EmbeddingService()
    
    def generate_exploit_embedding(self, exploit_data: Dict) -> np.ndarray:
        """
        Generate embedding for exploit entry
        
        Args:
            exploit_data: Dictionary with exploit information
            
        Returns:
            Embedding vector
        """
        text_parts = []
        
        if exploit_data.get('id'):
            text_parts.append(f"Exploit ID: {exploit_data['id']}")
        
        if exploit_data.get('title'):
            text_parts.append(f"Title: {exploit_data['title']}")
        
        if exploit_data.get('description'):
            text_parts.append(f"Description: {exploit_data['description']}")
        
        if exploit_data.get('platform'):
            text_parts.append(f"Platform: {exploit_data['platform']}")
        
        if exploit_data.get('type'):
            text_parts.append(f"Type: {exploit_data['type']}")
        
        if exploit_data.get('port'):
            text_parts.append(f"Port: {exploit_data['port']}")
        
        combined_text = ". ".join(text_parts)
        return self.embedding_service.generate_embedding(combined_text)
    
    def generate_exploit_embeddings_batch(
        self,
        exploit_data_list: List[Dict],
        show_progress: bool = True
    ) -> np.ndarray:
        """
        Generate embeddings for batch of exploits
        
        Args:
            exploit_data_list: List of exploit dictionaries
            show_progress: Show progress bar
            
        Returns:
            Array of embeddings
        """
        texts = []
        for exploit_data in exploit_data_list:
            text_parts = []
            
            if exploit_data.get('id'):
                text_parts.append(f"Exploit ID: {exploit_data['id']}")
            
            if exploit_data.get('title'):
                text_parts.append(f"Title: {exploit_data['title']}")
            
            if exploit_data.get('description'):
                text_parts.append(f"Description: {exploit_data['description']}")
            
            combined_text = ". ".join(text_parts)
            texts.append(combined_text)
        
        return self.embedding_service.generate_embeddings_batch(
            texts,
            show_progress=show_progress
        )


# Global singleton
_embedding_service: Optional[EmbeddingService] = None


def get_embedding_service() -> EmbeddingService:
    """Get or create embedding service singleton"""
    global _embedding_service
    if _embedding_service is None:
        _embedding_service = EmbeddingService()
    return _embedding_service
