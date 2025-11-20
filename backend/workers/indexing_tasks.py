"""
Vector Search Indexing Pipeline
Week 7-8: Background tasks for indexing CVEs and exploits into ChromaDB

Uses Celery for background processing and scheduled updates.
"""
import logging
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
import requests
from tqdm import tqdm

from workers.celery_app import celery_app
from core.chroma_manager import get_chroma_manager
from core.embedding_service import (
    get_embedding_service,
    CVEEmbeddingGenerator,
    ExploitEmbeddingGenerator
)


logger = logging.getLogger(__name__)


@celery_app.task(
    name="index_cves_task",
    bind=True,
    max_retries=3,
    default_retry_delay=300
)
def index_cves_task(
    self,
    cve_ids: Optional[List[str]] = None,
    batch_size: int = 50,
    force_reindex: bool = False
) -> Dict[str, Any]:
    """
    Index CVEs into ChromaDB with embeddings
    
    Args:
        cve_ids: Optional list of specific CVE IDs to index
        batch_size: Number of CVEs to process per batch
        force_reindex: Whether to reindex existing CVEs
        
    Returns:
        Task result with indexing statistics
    """
    logger.info("Starting CVE indexing task")
    
    try:
        chroma = get_chroma_manager()
        cve_generator = CVEEmbeddingGenerator()
        
        # Get CVEs to index
        if cve_ids:
            cves_to_index = _fetch_cves_by_ids(cve_ids)
        else:
            # Fetch recent CVEs from NVD API
            cves_to_index = _fetch_recent_cves(days=30)
        
        if not cves_to_index:
            logger.warning("No CVEs to index")
            return {
                "status": "completed",
                "cves_indexed": 0,
                "message": "No CVEs found to index"
            }
        
        logger.info(f"Indexing {len(cves_to_index)} CVEs")
        
        indexed_count = 0
        failed_count = 0
        
        # Process in batches
        for i in range(0, len(cves_to_index), batch_size):
            batch = cves_to_index[i:i + batch_size]
            
            try:
                # Generate embeddings for batch
                embeddings = cve_generator.generate_cve_embeddings_batch(batch)
                
                # Prepare documents and metadata
                cve_ids_batch = [cve['id'] for cve in batch]
                descriptions = [cve['description'] for cve in batch]
                metadata_list = [
                    {
                        'severity': cve.get('severity', 'UNKNOWN'),
                        'cvss_score': cve.get('cvss_score', 0.0),
                        'published_date': cve.get('published_date', ''),
                        'affected_products': ','.join(cve.get('affected_products', [])),
                        'vulnerability_type': cve.get('vulnerability_type', '')
                    }
                    for cve in batch
                ]
                
                # Add to ChromaDB
                chroma.add_cve_documents(
                    cve_ids=cve_ids_batch,
                    descriptions=descriptions,
                    metadata_list=metadata_list
                )
                
                indexed_count += len(batch)
                logger.info(f"Indexed batch {i//batch_size + 1}: {len(batch)} CVEs")
                
            except Exception as e:
                logger.error(f"Failed to index batch: {e}")
                failed_count += len(batch)
        
        return {
            "status": "completed",
            "cves_indexed": indexed_count,
            "failed": failed_count,
            "total": len(cves_to_index),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"CVE indexing task failed: {e}")
        raise self.retry(exc=e)


@celery_app.task(
    name="index_exploits_task",
    bind=True,
    max_retries=3,
    default_retry_delay=300
)
def index_exploits_task(
    self,
    exploit_ids: Optional[List[str]] = None,
    batch_size: int = 50,
    force_reindex: bool = False
) -> Dict[str, Any]:
    """
    Index exploits into ChromaDB with embeddings
    
    Args:
        exploit_ids: Optional list of specific exploit IDs
        batch_size: Number of exploits to process per batch
        force_reindex: Whether to reindex existing exploits
        
    Returns:
        Task result with indexing statistics
    """
    logger.info("Starting exploit indexing task")
    
    try:
        chroma = get_chroma_manager()
        exploit_generator = ExploitEmbeddingGenerator()
        
        # Get exploits to index
        if exploit_ids:
            exploits_to_index = _fetch_exploits_by_ids(exploit_ids)
        else:
            # Fetch recent exploits
            exploits_to_index = _fetch_recent_exploits(limit=1000)
        
        if not exploits_to_index:
            logger.warning("No exploits to index")
            return {
                "status": "completed",
                "exploits_indexed": 0,
                "message": "No exploits found to index"
            }
        
        logger.info(f"Indexing {len(exploits_to_index)} exploits")
        
        indexed_count = 0
        failed_count = 0
        
        # Process in batches
        for i in range(0, len(exploits_to_index), batch_size):
            batch = exploits_to_index[i:i + batch_size]
            
            try:
                # Generate embeddings for batch
                embeddings = exploit_generator.generate_exploit_embeddings_batch(batch)
                
                # Prepare documents and metadata
                exploit_ids_batch = [exp['id'] for exp in batch]
                descriptions = [exp['description'] for exp in batch]
                metadata_list = [
                    {
                        'title': exp.get('title', ''),
                        'platform': exp.get('platform', ''),
                        'type': exp.get('type', ''),
                        'port': exp.get('port', 0),
                        'published_date': exp.get('published_date', '')
                    }
                    for exp in batch
                ]
                
                # Add to ChromaDB
                chroma.add_exploit_documents(
                    exploit_ids=exploit_ids_batch,
                    descriptions=descriptions,
                    metadata_list=metadata_list
                )
                
                indexed_count += len(batch)
                logger.info(f"Indexed batch {i//batch_size + 1}: {len(batch)} exploits")
                
            except Exception as e:
                logger.error(f"Failed to index batch: {e}")
                failed_count += len(batch)
        
        return {
            "status": "completed",
            "exploits_indexed": indexed_count,
            "failed": failed_count,
            "total": len(exploits_to_index),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Exploit indexing task failed: {e}")
        raise self.retry(exc=e)


@celery_app.task(
    name="index_security_knowledge_task",
    bind=True,
    max_retries=3,
    default_retry_delay=300
)
def index_security_knowledge_task(
    self,
    knowledge_sources: Optional[List[Dict]] = None,
    batch_size: int = 20
) -> Dict[str, Any]:
    """
    Index security knowledge base (advisories, best practices)
    
    Args:
        knowledge_sources: Optional list of knowledge sources
        batch_size: Number of documents to process per batch
        
    Returns:
        Task result with indexing statistics
    """
    logger.info("Starting security knowledge indexing task")
    
    try:
        chroma = get_chroma_manager()
        embedding_service = get_embedding_service()
        
        # Get knowledge documents
        if knowledge_sources:
            docs_to_index = knowledge_sources
        else:
            # Fetch default security knowledge
            docs_to_index = _fetch_security_knowledge()
        
        if not docs_to_index:
            logger.warning("No knowledge documents to index")
            return {
                "status": "completed",
                "documents_indexed": 0,
                "message": "No documents found to index"
            }
        
        logger.info(f"Indexing {len(docs_to_index)} knowledge documents")
        
        indexed_count = 0
        
        # Process in batches
        for i in range(0, len(docs_to_index), batch_size):
            batch = docs_to_index[i:i + batch_size]
            
            try:
                # Prepare data
                doc_ids = [doc['id'] for doc in batch]
                contents = [doc['content'] for doc in batch]
                metadata_list = [
                    {
                        'topic': doc.get('topic', ''),
                        'source': doc.get('source', ''),
                        'category': doc.get('category', ''),
                        'updated_date': doc.get('updated_date', '')
                    }
                    for doc in batch
                ]
                
                # Add to ChromaDB
                chroma.add_security_knowledge(
                    doc_ids=doc_ids,
                    contents=contents,
                    metadata_list=metadata_list
                )
                
                indexed_count += len(batch)
                logger.info(f"Indexed batch {i//batch_size + 1}: {len(batch)} documents")
                
            except Exception as e:
                logger.error(f"Failed to index batch: {e}")
        
        return {
            "status": "completed",
            "documents_indexed": indexed_count,
            "total": len(docs_to_index),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Knowledge indexing task failed: {e}")
        raise self.retry(exc=e)


@celery_app.task(name="update_vector_db_task")
def update_vector_db_task() -> Dict[str, Any]:
    """
    Scheduled task to update entire vector database
    Runs daily to index new CVEs and exploits
    
    Returns:
        Summary of update operation
    """
    logger.info("Running scheduled vector DB update")
    
    results = {
        "timestamp": datetime.now().isoformat(),
        "tasks_completed": []
    }
    
    # Index recent CVEs
    cve_result = index_cves_task.delay()
    results["tasks_completed"].append({
        "task": "index_cves",
        "task_id": cve_result.id
    })
    
    # Index recent exploits
    exploit_result = index_exploits_task.delay()
    results["tasks_completed"].append({
        "task": "index_exploits",
        "task_id": exploit_result.id
    })
    
    # Index security knowledge
    knowledge_result = index_security_knowledge_task.delay()
    results["tasks_completed"].append({
        "task": "index_security_knowledge",
        "task_id": knowledge_result.id
    })
    
    return results


# Helper functions for fetching data

def _fetch_recent_cves(days: int = 30) -> List[Dict]:
    """
    Fetch recent CVEs from NVD API
    
    Args:
        days: Number of days to look back
        
    Returns:
        List of CVE dictionaries
    """
    logger.info(f"Fetching CVEs from last {days} days")
    
    # This is a placeholder - implement actual NVD API integration
    # For now, return sample data for testing
    return []


def _fetch_cves_by_ids(cve_ids: List[str]) -> List[Dict]:
    """Fetch specific CVEs by ID"""
    logger.info(f"Fetching {len(cve_ids)} specific CVEs")
    
    # Placeholder - implement actual CVE fetching
    return []


def _fetch_recent_exploits(limit: int = 1000) -> List[Dict]:
    """
    Fetch recent exploits from ExploitDB
    
    Args:
        limit: Maximum number of exploits to fetch
        
    Returns:
        List of exploit dictionaries
    """
    logger.info(f"Fetching up to {limit} recent exploits")
    
    # Placeholder - implement actual ExploitDB integration
    return []


def _fetch_exploits_by_ids(exploit_ids: List[str]) -> List[Dict]:
    """Fetch specific exploits by ID"""
    logger.info(f"Fetching {len(exploit_ids)} specific exploits")
    
    # Placeholder - implement actual exploit fetching
    return []


def _fetch_security_knowledge() -> List[Dict]:
    """
    Fetch security knowledge base documents
    
    Returns:
        List of knowledge documents
    """
    logger.info("Fetching security knowledge base")
    
    # Sample security knowledge
    knowledge_docs = [
        {
            'id': 'sk_001',
            'content': 'SQL Injection Prevention: Use parameterized queries, prepared statements, and input validation. Never concatenate user input directly into SQL queries.',
            'topic': 'SQL Injection',
            'source': 'OWASP',
            'category': 'Web Security',
            'updated_date': datetime.now().isoformat()
        },
        {
            'id': 'sk_002',
            'content': 'XSS Prevention: Sanitize all user input, use Content Security Policy (CSP), encode output, and validate input on both client and server.',
            'topic': 'Cross-Site Scripting',
            'source': 'OWASP',
            'category': 'Web Security',
            'updated_date': datetime.now().isoformat()
        },
        {
            'id': 'sk_003',
            'content': 'Authentication Best Practices: Use strong password policies, implement multi-factor authentication, use secure session management, and hash passwords with bcrypt or Argon2.',
            'topic': 'Authentication',
            'source': 'NIST',
            'category': 'Identity & Access',
            'updated_date': datetime.now().isoformat()
        },
        {
            'id': 'sk_004',
            'content': 'CSRF Protection: Use anti-CSRF tokens, verify Origin/Referer headers, implement SameSite cookie attributes, and require re-authentication for sensitive actions.',
            'topic': 'CSRF',
            'source': 'OWASP',
            'category': 'Web Security',
            'updated_date': datetime.now().isoformat()
        },
        {
            'id': 'sk_005',
            'content': 'Encryption Best Practices: Use TLS 1.3, strong cipher suites, proper key management, and encrypt sensitive data at rest and in transit.',
            'topic': 'Encryption',
            'source': 'NIST',
            'category': 'Cryptography',
            'updated_date': datetime.now().isoformat()
        }
    ]
    
    return knowledge_docs


# Celery beat schedule for periodic tasks
# Add to celery_app.py:
# from celery.schedules import crontab
#
# celery_app.conf.beat_schedule = {
#     'update-vector-db-daily': {
#         'task': 'update_vector_db_task',
#         'schedule': crontab(hour=2, minute=0),  # Run at 2 AM daily
#     },
# }
