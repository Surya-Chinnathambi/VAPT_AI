"""
ChromaDB Integration for Vector Search
Handles CVE embeddings and Compliance Framework embeddings
"""
try:
    import chromadb
    from chromadb.config import Settings
    from chromadb.utils import embedding_functions
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False
    chromadb = None
    Settings = None
    embedding_functions = None

import logging
from typing import List, Dict, Any
import json

from config import CHROMA_PERSIST_DIR, AZURE_OPENAI_KEY, AZURE_OPENAI_ENDPOINT

logger = logging.getLogger(__name__)

class VectorDBManager:
    def __init__(self):
        if not CHROMADB_AVAILABLE:
            logger.warning("ChromaDB not available - vector search features disabled")
            self.client = None
            self.cve_collection = None
            self.compliance_collection = None
            return
        
        try:
            # Try to connect to Docker ChromaDB server
            self.client = chromadb.HttpClient(host="localhost", port=8001)
            # Test connection
            self.client.heartbeat()
            logger.info("Connected to ChromaDB server on localhost:8001")
            
            # Use default embeddings (no Azure OpenAI needed for now)
            # Initialize collections
            self.cve_collection = self._get_or_create_collection("cves")
            self.compliance_collection = self._get_or_create_collection("compliance_frameworks")
        except Exception as e:
            logger.warning(f"Could not connect to ChromaDB server: {e}. Vector search disabled.")
            self.client = None
            self.cve_collection = None
            self.compliance_collection = None
            return
    
    def _get_or_create_collection(self, name: str):
        """Get or create a collection"""
        if not self.client:
            return None
        try:
            return self.client.get_or_create_collection(
                name=name,
                metadata={"hnsw:space": "cosine"}
            )
        except Exception as e:
            logger.error(f"Error creating collection {name}: {e}")
            return None
    
    # CVE Operations
    def add_cve(self, cve_id: str, description: str, metadata: Dict[str, Any]):
        """Add CVE to vector database"""
        if not CHROMADB_AVAILABLE or not self.client:
            return
        try:
            self.cve_collection.add(
                ids=[cve_id],
                documents=[description],
                metadatas=[metadata]
            )
            logger.info(f"Added CVE {cve_id} to vector database")
        except Exception as e:
            logger.error(f"Error adding CVE {cve_id}: {e}")
    
    def add_cves_batch(self, cves: List[Dict[str, Any]]):
        """Add multiple CVEs in batch"""
        if not CHROMADB_AVAILABLE or not self.client:
            return
        try:
            ids = [cve['cve_id'] for cve in cves]
            documents = [cve['description'] for cve in cves]
            metadatas = [{
                'cvss_score': cve.get('cvss_v3_score', 0),
                'severity': cve.get('severity', 'UNKNOWN'),
                'published_date': str(cve.get('published_date', '')),
                'cwe_ids': json.dumps(cve.get('cwe_ids', []))
            } for cve in cves]
            
            self.cve_collection.add(
                ids=ids,
                documents=documents,
                metadatas=metadatas
            )
            logger.info(f"Added {len(cves)} CVEs to vector database")
        except Exception as e:
            logger.error(f"Error adding CVEs batch: {e}")
    
    def search_cves(self, query: str, n_results: int = 10, severity_filter: str = None):
        """Search CVEs by semantic similarity"""
        if not CHROMADB_AVAILABLE or not self.client:
            return {"ids": [], "distances": [], "metadatas": [], "documents": []}
        try:
            where_filter = {}
            if severity_filter:
                where_filter = {"severity": severity_filter}
            
            results = self.cve_collection.query(
                query_texts=[query],
                n_results=n_results,
                where=where_filter if where_filter else None
            )
            
            return {
                'ids': results['ids'][0],
                'documents': results['documents'][0],
                'metadatas': results['metadatas'][0],
                'distances': results['distances'][0]
            }
        except Exception as e:
            logger.error(f"Error searching CVEs: {e}")
            return {'ids': [], 'documents': [], 'metadatas': [], 'distances': []}
    
    def get_cve_by_id(self, cve_id: str):
        """Get specific CVE by ID"""
        try:
            result = self.cve_collection.get(ids=[cve_id])
            if result['ids']:
                return {
                    'id': result['ids'][0],
                    'document': result['documents'][0],
                    'metadata': result['metadatas'][0]
                }
            return None
        except Exception as e:
            logger.error(f"Error getting CVE {cve_id}: {e}")
            return None
    
    # Compliance Framework Operations
    def add_compliance_requirement(self, framework_code: str, requirement_id: str, 
                                   requirement_text: str, metadata: Dict[str, Any]):
        """Add compliance requirement to vector database"""
        try:
            doc_id = f"{framework_code}_{requirement_id}"
            self.compliance_collection.add(
                ids=[doc_id],
                documents=[requirement_text],
                metadatas={
                    'framework_code': framework_code,
                    'requirement_id': requirement_id,
                    **metadata
                }
            )
            logger.info(f"Added compliance requirement {doc_id}")
        except Exception as e:
            logger.error(f"Error adding compliance requirement: {e}")
    
    def add_compliance_batch(self, requirements: List[Dict[str, Any]]):
        """Add multiple compliance requirements"""
        try:
            ids = [f"{req['framework_code']}_{req['requirement_id']}" for req in requirements]
            documents = [req['requirement_text'] for req in requirements]
            metadatas = [{
                'framework_code': req['framework_code'],
                'requirement_id': req['requirement_id'],
                'category': req.get('category', ''),
                'control_number': req.get('control_number', '')
            } for req in requirements]
            
            self.compliance_collection.add(
                ids=ids,
                documents=documents,
                metadatas=metadatas
            )
            logger.info(f"Added {len(requirements)} compliance requirements")
        except Exception as e:
            logger.error(f"Error adding compliance batch: {e}")
    
    def search_compliance(self, query: str, framework_code: str = None, n_results: int = 10):
        """Search compliance requirements by semantic similarity"""
        try:
            where_filter = {}
            if framework_code:
                where_filter = {"framework_code": framework_code}
            
            results = self.compliance_collection.query(
                query_texts=[query],
                n_results=n_results,
                where=where_filter if where_filter else None
            )
            
            return {
                'ids': results['ids'][0],
                'documents': results['documents'][0],
                'metadatas': results['metadatas'][0],
                'distances': results['distances'][0]
            }
        except Exception as e:
            logger.error(f"Error searching compliance: {e}")
            return {'ids': [], 'documents': [], 'metadatas': [], 'distances': []}
    
    def map_vulnerability_to_compliance(self, vulnerability_description: str, 
                                       frameworks: List[str] = None, n_results: int = 5):
        """Map a vulnerability to relevant compliance requirements"""
        results = []
        
        if frameworks:
            for framework in frameworks:
                framework_results = self.search_compliance(
                    vulnerability_description, 
                    framework_code=framework,
                    n_results=n_results
                )
                results.extend([
                    {
                        'framework': framework,
                        'requirement_id': framework_results['metadatas'][i]['requirement_id'],
                        'requirement_text': framework_results['documents'][i],
                        'relevance_score': 1 - framework_results['distances'][i]
                    }
                    for i in range(len(framework_results['ids']))
                ])
        else:
            all_results = self.search_compliance(vulnerability_description, n_results=n_results)
            results = [
                {
                    'framework': all_results['metadatas'][i]['framework_code'],
                    'requirement_id': all_results['metadatas'][i]['requirement_id'],
                    'requirement_text': all_results['documents'][i],
                    'relevance_score': 1 - all_results['distances'][i]
                }
                for i in range(len(all_results['ids']))
            ]
        
        return results
    
    def persist(self):
        """Persist the database to disk"""
        try:
            self.client.persist()
            logger.info("ChromaDB persisted successfully")
        except Exception as e:
            logger.error(f"Error persisting ChromaDB: {e}")

# Global instance
vector_db = None

def get_vector_db() -> VectorDBManager:
    """Get or create vector database instance"""
    global vector_db
    if vector_db is None:
        vector_db = VectorDBManager()
    return vector_db
