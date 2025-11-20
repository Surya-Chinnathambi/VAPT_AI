"""
ChromaDB Vector Database Manager
Week 7-8: Vector Search Implementation

Manages ChromaDB collections for CVEs, exploits, and security knowledge.
Provides vector similarity search and hybrid search capabilities.
"""
import os
import logging
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime
import chromadb
from chromadb.config import Settings
from chromadb.utils import embedding_functions


logger = logging.getLogger(__name__)


class ChromaDBManager:
    """Manages ChromaDB vector database for semantic search"""
    
    def __init__(self, persist_directory: Optional[str] = None):
        """
        Initialize ChromaDB client
        
        Args:
            persist_directory: Directory to persist database (default: ./chroma_db)
        """
        if persist_directory is None:
            persist_directory = os.getenv("CHROMA_DB_PATH", "./chroma_db")
        
        self.persist_directory = persist_directory
        
        # Initialize ChromaDB client with persistence
        self.client = chromadb.PersistentClient(
            path=persist_directory,
            settings=Settings(
                anonymized_telemetry=False,
                allow_reset=True
            )
        )
        
        # Collection names
        self.CVE_COLLECTION = "cve_vulnerabilities"
        self.EXPLOIT_COLLECTION = "exploits"
        self.SECURITY_KNOWLEDGE_COLLECTION = "security_knowledge"
        
        logger.info(f"ChromaDB initialized at {persist_directory}")
    
    def _get_embedding_function(self):
        """Get default embedding function (sentence-transformers)"""
        return embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"  # Fast, good quality embeddings
        )
    
    def get_or_create_collection(
        self,
        collection_name: str,
        metadata: Optional[Dict] = None
    ) -> chromadb.Collection:
        """
        Get existing collection or create new one
        
        Args:
            collection_name: Name of collection
            metadata: Optional metadata for collection
            
        Returns:
            ChromaDB collection
        """
        try:
            collection = self.client.get_collection(
                name=collection_name,
                embedding_function=self._get_embedding_function()
            )
            logger.info(f"Retrieved existing collection: {collection_name}")
            return collection
        except Exception:
            # Collection doesn't exist, create it
            collection = self.client.create_collection(
                name=collection_name,
                embedding_function=self._get_embedding_function(),
                metadata=metadata or {"created_at": datetime.now().isoformat()}
            )
            logger.info(f"Created new collection: {collection_name}")
            return collection
    
    def add_cve_documents(
        self,
        cve_ids: List[str],
        descriptions: List[str],
        metadata_list: List[Dict]
    ) -> None:
        """
        Add CVE documents to vector database
        
        Args:
            cve_ids: List of CVE IDs (e.g., CVE-2023-12345)
            descriptions: List of CVE descriptions
            metadata_list: List of metadata dicts (severity, cvss, etc.)
        """
        collection = self.get_or_create_collection(self.CVE_COLLECTION)
        
        try:
            collection.add(
                ids=cve_ids,
                documents=descriptions,
                metadatas=metadata_list
            )
            logger.info(f"Added {len(cve_ids)} CVE documents to database")
        except Exception as e:
            logger.error(f"Failed to add CVE documents: {e}")
            raise
    
    def add_exploit_documents(
        self,
        exploit_ids: List[str],
        descriptions: List[str],
        metadata_list: List[Dict]
    ) -> None:
        """
        Add exploit documents to vector database
        
        Args:
            exploit_ids: List of exploit IDs (EDB-12345)
            descriptions: List of exploit descriptions
            metadata_list: List of metadata dicts (platform, type, etc.)
        """
        collection = self.get_or_create_collection(self.EXPLOIT_COLLECTION)
        
        try:
            collection.add(
                ids=exploit_ids,
                documents=descriptions,
                metadatas=metadata_list
            )
            logger.info(f"Added {len(exploit_ids)} exploit documents to database")
        except Exception as e:
            logger.error(f"Failed to add exploit documents: {e}")
            raise
    
    def add_security_knowledge(
        self,
        doc_ids: List[str],
        documents: List[str],
        metadata_list: List[Dict]
    ) -> None:
        """
        Add security knowledge documents (advisories, best practices, etc.)
        
        Args:
            doc_ids: List of document IDs
            documents: List of document texts
            metadata_list: List of metadata dicts
        """
        collection = self.get_or_create_collection(self.SECURITY_KNOWLEDGE_COLLECTION)
        
        try:
            collection.add(
                ids=doc_ids,
                documents=documents,
                metadatas=metadata_list
            )
            logger.info(f"Added {len(doc_ids)} security knowledge documents")
        except Exception as e:
            logger.error(f"Failed to add security knowledge: {e}")
            raise
    
    def search_cves(
        self,
        query: str,
        n_results: int = 10,
        where: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Search CVEs using vector similarity
        
        Args:
            query: Search query text
            n_results: Number of results to return
            where: Optional metadata filters (e.g., {"severity": "HIGH"})
            
        Returns:
            Dictionary with ids, documents, metadatas, distances
        """
        collection = self.get_or_create_collection(self.CVE_COLLECTION)
        
        try:
            results = collection.query(
                query_texts=[query],
                n_results=n_results,
                where=where
            )
            logger.info(f"CVE search for '{query}': {len(results['ids'][0])} results")
            return self._format_results(results)
        except Exception as e:
            logger.error(f"CVE search failed: {e}")
            return {"ids": [], "documents": [], "metadatas": [], "distances": []}
    
    def search_exploits(
        self,
        query: str,
        n_results: int = 10,
        where: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Search exploits using vector similarity
        
        Args:
            query: Search query text
            n_results: Number of results to return
            where: Optional metadata filters
            
        Returns:
            Dictionary with search results
        """
        collection = self.get_or_create_collection(self.EXPLOIT_COLLECTION)
        
        try:
            results = collection.query(
                query_texts=[query],
                n_results=n_results,
                where=where
            )
            logger.info(f"Exploit search for '{query}': {len(results['ids'][0])} results")
            return self._format_results(results)
        except Exception as e:
            logger.error(f"Exploit search failed: {e}")
            return {"ids": [], "documents": [], "metadatas": [], "distances": []}
    
    def search_security_knowledge(
        self,
        query: str,
        n_results: int = 5,
        where: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Search security knowledge base
        
        Args:
            query: Search query text
            n_results: Number of results to return
            where: Optional metadata filters
            
        Returns:
            Dictionary with search results
        """
        collection = self.get_or_create_collection(self.SECURITY_KNOWLEDGE_COLLECTION)
        
        try:
            results = collection.query(
                query_texts=[query],
                n_results=n_results,
                where=where
            )
            logger.info(f"Knowledge search for '{query}': {len(results['ids'][0])} results")
            return self._format_results(results)
        except Exception as e:
            logger.error(f"Knowledge search failed: {e}")
            return {"ids": [], "documents": [], "metadatas": [], "distances": []}
    
    def hybrid_search(
        self,
        query: str,
        collections: List[str],
        n_results: int = 10
    ) -> Dict[str, List[Dict]]:
        """
        Search across multiple collections
        
        Args:
            query: Search query text
            collections: List of collection names to search
            n_results: Number of results per collection
            
        Returns:
            Dictionary mapping collection names to results
        """
        all_results = {}
        
        for collection_name in collections:
            if collection_name == self.CVE_COLLECTION:
                all_results['cves'] = self.search_cves(query, n_results)
            elif collection_name == self.EXPLOIT_COLLECTION:
                all_results['exploits'] = self.search_exploits(query, n_results)
            elif collection_name == self.SECURITY_KNOWLEDGE_COLLECTION:
                all_results['knowledge'] = self.search_security_knowledge(query, n_results)
        
        return all_results
    
    def _format_results(self, results: Dict) -> Dict[str, Any]:
        """
        Format ChromaDB results into consistent structure
        
        Args:
            results: Raw ChromaDB query results
            
        Returns:
            Formatted results dictionary
        """
        if not results['ids'] or not results['ids'][0]:
            return {"ids": [], "documents": [], "metadatas": [], "distances": []}
        
        return {
            "ids": results['ids'][0],
            "documents": results['documents'][0],
            "metadatas": results['metadatas'][0],
            "distances": results['distances'][0]
        }
    
    def get_collection_stats(self, collection_name: str) -> Dict[str, Any]:
        """
        Get statistics about a collection
        
        Args:
            collection_name: Name of collection
            
        Returns:
            Dictionary with collection statistics
        """
        try:
            collection = self.client.get_collection(
                name=collection_name,
                embedding_function=self._get_embedding_function()
            )
            
            count = collection.count()
            
            return {
                "name": collection_name,
                "count": count,
                "metadata": collection.metadata
            }
        except Exception as e:
            logger.error(f"Failed to get collection stats: {e}")
            return {
                "name": collection_name,
                "count": 0,
                "error": str(e)
            }
    
    def delete_collection(self, collection_name: str) -> bool:
        """
        Delete a collection
        
        Args:
            collection_name: Name of collection to delete
            
        Returns:
            True if deleted, False otherwise
        """
        try:
            self.client.delete_collection(name=collection_name)
            logger.info(f"Deleted collection: {collection_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete collection {collection_name}: {e}")
            return False
    
    def reset_database(self) -> bool:
        """
        Reset entire database (use with caution!)
        
        Returns:
            True if reset successful
        """
        try:
            self.client.reset()
            logger.warning("ChromaDB database reset!")
            return True
        except Exception as e:
            logger.error(f"Failed to reset database: {e}")
            return False


# Global singleton
_chroma_manager: Optional[ChromaDBManager] = None


def get_chroma_manager() -> ChromaDBManager:
    """Get or create ChromaDB manager singleton"""
    global _chroma_manager
    if _chroma_manager is None:
        _chroma_manager = ChromaDBManager()
    return _chroma_manager
