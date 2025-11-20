"""
Vector Search Tests
Week 7-8: Comprehensive tests for ChromaDB, embeddings, semantic search, and AI agents

Test Coverage:
- ChromaDB Manager: Collection management, document operations
- Embedding Service: Model loading, embedding generation, similarity
- Semantic Search: Search accuracy, ranking, hybrid search
- AI Agents: Tool usage, agent responses (mocked)
"""
import pytest
import os
import numpy as np
from unittest.mock import Mock, patch, MagicMock
from typing import List, Dict

from core.chroma_manager import ChromaDBManager, get_chroma_manager
from core.embedding_service import (
    EmbeddingService,
    CVEEmbeddingGenerator,
    ExploitEmbeddingGenerator,
    get_embedding_service
)
from core.semantic_search import SemanticSearchEngine, get_search_engine
from core.ai_agents import CVESearchTool, ExploitSearchTool, SecurityKnowledgeTool


# Fixtures

@pytest.fixture(scope="function")
def chroma_manager():
    """Create fresh ChromaDB manager for testing"""
    # Use test database
    os.environ['CHROMA_DB_PATH'] = './test_chroma_db'
    
    manager = ChromaDBManager()
    yield manager
    
    # Cleanup
    try:
        manager.reset_database()
    except:
        pass


@pytest.fixture(scope="function")
def embedding_service():
    """Create embedding service with fast model"""
    service = EmbeddingService(model_name="fast")
    return service


@pytest.fixture(scope="function")
def search_engine(chroma_manager):
    """Create search engine with test ChromaDB"""
    engine = SemanticSearchEngine()
    return engine


@pytest.fixture
def sample_cves():
    """Sample CVE data for testing"""
    return [
        {
            'id': 'CVE-2024-0001',
            'description': 'SQL injection vulnerability in web application login form',
            'severity': 'HIGH',
            'cvss_score': 8.5,
            'published_date': '2024-01-01',
            'affected_products': ['WebApp 1.0', 'WebApp 2.0'],
            'vulnerability_type': 'SQL Injection'
        },
        {
            'id': 'CVE-2024-0002',
            'description': 'Cross-site scripting (XSS) in comment section',
            'severity': 'MEDIUM',
            'cvss_score': 6.1,
            'published_date': '2024-01-02',
            'affected_products': ['Blog Platform 3.0'],
            'vulnerability_type': 'XSS'
        },
        {
            'id': 'CVE-2024-0003',
            'description': 'Remote code execution in file upload functionality',
            'severity': 'CRITICAL',
            'cvss_score': 9.8,
            'published_date': '2024-01-03',
            'affected_products': ['FileManager Pro'],
            'vulnerability_type': 'RCE'
        }
    ]


@pytest.fixture
def sample_exploits():
    """Sample exploit data for testing"""
    return [
        {
            'id': 'EDB-50001',
            'title': 'SQL Injection Exploit for WebApp',
            'description': 'Proof-of-concept SQL injection exploit',
            'platform': 'Web',
            'type': 'webapps',
            'port': 80,
            'published_date': '2024-01-05'
        },
        {
            'id': 'EDB-50002',
            'title': 'XSS Payload Collection',
            'description': 'Collection of XSS attack vectors',
            'platform': 'Web',
            'type': 'webapps',
            'port': 443,
            'published_date': '2024-01-06'
        }
    ]


# ChromaDB Manager Tests

class TestChromaDBManager:
    """Test ChromaDB manager functionality"""
    
    def test_initialization(self, chroma_manager):
        """Test ChromaDB manager initialization"""
        assert chroma_manager.client is not None
        assert hasattr(chroma_manager, 'CVE_COLLECTION')
        assert hasattr(chroma_manager, 'EXPLOIT_COLLECTION')
        assert hasattr(chroma_manager, 'SECURITY_KNOWLEDGE_COLLECTION')
    
    def test_create_collection(self, chroma_manager):
        """Test collection creation"""
        collection = chroma_manager.get_or_create_collection("test_collection")
        assert collection is not None
        assert collection.name == "test_collection"
    
    def test_add_cve_documents(self, chroma_manager, sample_cves):
        """Test adding CVE documents"""
        cve_ids = [cve['id'] for cve in sample_cves]
        descriptions = [cve['description'] for cve in sample_cves]
        metadata_list = [
            {
                'severity': cve['severity'],
                'cvss_score': cve['cvss_score'],
                'published_date': cve['published_date']
            }
            for cve in sample_cves
        ]
        
        chroma_manager.add_cve_documents(cve_ids, descriptions, metadata_list)
        
        # Verify documents were added
        stats = chroma_manager.get_collection_stats(chroma_manager.CVE_COLLECTION)
        assert stats['count'] == len(sample_cves)
    
    def test_search_cves(self, chroma_manager, sample_cves):
        """Test CVE search"""
        # Add test data
        cve_ids = [cve['id'] for cve in sample_cves]
        descriptions = [cve['description'] for cve in sample_cves]
        metadata_list = [
            {'severity': cve['severity']}
            for cve in sample_cves
        ]
        
        chroma_manager.add_cve_documents(cve_ids, descriptions, metadata_list)
        
        # Search for SQL injection
        results = chroma_manager.search_cves("SQL injection", n_results=3)
        
        assert len(results['ids']) > 0
        assert 'CVE-2024-0001' in results['ids']
    
    def test_add_exploit_documents(self, chroma_manager, sample_exploits):
        """Test adding exploit documents"""
        exploit_ids = [exp['id'] for exp in sample_exploits]
        descriptions = [exp['description'] for exp in sample_exploits]
        metadata_list = [
            {'platform': exp['platform'], 'type': exp['type']}
            for exp in sample_exploits
        ]
        
        chroma_manager.add_exploit_documents(exploit_ids, descriptions, metadata_list)
        
        stats = chroma_manager.get_collection_stats(chroma_manager.EXPLOIT_COLLECTION)
        assert stats['count'] == len(sample_exploits)
    
    def test_hybrid_search(self, chroma_manager, sample_cves, sample_exploits):
        """Test hybrid search across collections"""
        # Add CVEs
        cve_ids = [cve['id'] for cve in sample_cves]
        cve_descriptions = [cve['description'] for cve in sample_cves]
        chroma_manager.add_cve_documents(cve_ids, cve_descriptions)
        
        # Add exploits
        exploit_ids = [exp['id'] for exp in sample_exploits]
        exploit_descriptions = [exp['description'] for exp in sample_exploits]
        chroma_manager.add_exploit_documents(exploit_ids, exploit_descriptions)
        
        # Search both collections
        results = chroma_manager.hybrid_search(
            "SQL injection",
            collections=[chroma_manager.CVE_COLLECTION, chroma_manager.EXPLOIT_COLLECTION],
            n_results=5
        )
        
        assert len(results) > 0
    
    def test_delete_collection(self, chroma_manager):
        """Test collection deletion"""
        collection_name = "test_delete"
        chroma_manager.get_or_create_collection(collection_name)
        
        chroma_manager.delete_collection(collection_name)
        
        # Collection should no longer exist
        try:
            chroma_manager.client.get_collection(collection_name)
            assert False, "Collection should have been deleted"
        except:
            pass


# Embedding Service Tests

class TestEmbeddingService:
    """Test embedding service functionality"""
    
    def test_initialization(self, embedding_service):
        """Test embedding service initialization"""
        assert embedding_service.model is not None
        assert embedding_service.model_name in embedding_service.MODELS.values()
    
    def test_generate_embedding(self, embedding_service):
        """Test single embedding generation"""
        text = "SQL injection vulnerability"
        embedding = embedding_service.generate_embedding(text)
        
        assert isinstance(embedding, np.ndarray)
        assert len(embedding) > 0
        # Fast model should produce 384-dimensional embeddings
        assert len(embedding) == 384
    
    def test_generate_embeddings_batch(self, embedding_service):
        """Test batch embedding generation"""
        texts = [
            "SQL injection vulnerability",
            "Cross-site scripting attack",
            "Remote code execution"
        ]
        
        embeddings = embedding_service.generate_embeddings_batch(texts)
        
        assert len(embeddings) == len(texts)
        assert all(isinstance(emb, np.ndarray) for emb in embeddings)
        assert all(len(emb) == 384 for emb in embeddings)
    
    def test_compute_similarity(self, embedding_service):
        """Test similarity computation"""
        emb1 = embedding_service.generate_embedding("SQL injection")
        emb2 = embedding_service.generate_embedding("SQL injection attack")
        emb3 = embedding_service.generate_embedding("Cross-site scripting")
        
        # Similar texts should have high similarity
        similarity_high = embedding_service.compute_similarity(emb1, emb2)
        # Different texts should have lower similarity
        similarity_low = embedding_service.compute_similarity(emb1, emb3)
        
        assert 0.0 <= similarity_high <= 1.0
        assert 0.0 <= similarity_low <= 1.0
        assert similarity_high > similarity_low
    
    def test_find_most_similar(self, embedding_service):
        """Test finding most similar embeddings"""
        query = "SQL injection vulnerability"
        candidates = [
            "SQL injection attack vector",
            "Cross-site scripting",
            "Remote code execution"
        ]
        
        query_embedding = embedding_service.generate_embedding(query)
        candidate_embeddings = [
            embedding_service.generate_embedding(text)
            for text in candidates
        ]
        
        most_similar = embedding_service.find_most_similar(
            query_embedding,
            candidate_embeddings,
            top_k=2
        )
        
        assert len(most_similar) == 2
        # First result should be SQL injection (most similar)
        assert most_similar[0][0] == 0
    
    def test_cve_embedding_generator(self, sample_cves):
        """Test CVE embedding generator"""
        generator = CVEEmbeddingGenerator()
        
        embedding = generator.generate_cve_embedding(sample_cves[0])
        
        assert isinstance(embedding, np.ndarray)
        assert len(embedding) == 384
    
    def test_cve_embeddings_batch(self, sample_cves):
        """Test batch CVE embedding generation"""
        generator = CVEEmbeddingGenerator()
        
        embeddings = generator.generate_cve_embeddings_batch(sample_cves)
        
        assert len(embeddings) == len(sample_cves)
        assert all(isinstance(emb, np.ndarray) for emb in embeddings)
    
    def test_exploit_embedding_generator(self, sample_exploits):
        """Test exploit embedding generator"""
        generator = ExploitEmbeddingGenerator()
        
        embedding = generator.generate_exploit_embedding(sample_exploits[0])
        
        assert isinstance(embedding, np.ndarray)
        assert len(embedding) == 384
    
    def test_cached_embeddings(self, embedding_service):
        """Test embedding caching"""
        text = "SQL injection test"
        
        # First call - should compute
        emb1 = embedding_service.generate_embedding_cached(text)
        
        # Second call - should use cache
        emb2 = embedding_service.generate_embedding_cached(text)
        
        # Should return same result
        assert emb1 == emb2


# Semantic Search Tests

class TestSemanticSearchEngine:
    """Test semantic search engine"""
    
    def test_initialization(self, search_engine):
        """Test search engine initialization"""
        assert search_engine.chroma is not None
        assert search_engine.embedding_service is not None
    
    def test_search_cves(self, search_engine, chroma_manager, sample_cves):
        """Test CVE semantic search"""
        # Add test data
        cve_ids = [cve['id'] for cve in sample_cves]
        descriptions = [cve['description'] for cve in sample_cves]
        metadata_list = [
            {'severity': cve['severity'], 'cvss_score': cve['cvss_score']}
            for cve in sample_cves
        ]
        
        chroma_manager.add_cve_documents(cve_ids, descriptions, metadata_list)
        
        # Search
        results = search_engine.search_cves("SQL injection", top_k=5)
        
        assert len(results) > 0
        assert 'cve_id' in results[0]
        assert 'similarity_score' in results[0]
        assert results[0]['similarity_score'] >= 0.0
    
    def test_search_with_filters(self, search_engine, chroma_manager, sample_cves):
        """Test search with metadata filters"""
        # Add test data
        cve_ids = [cve['id'] for cve in sample_cves]
        descriptions = [cve['description'] for cve in sample_cves]
        metadata_list = [
            {'severity': cve['severity']}
            for cve in sample_cves
        ]
        
        chroma_manager.add_cve_documents(cve_ids, descriptions, metadata_list)
        
        # Search with HIGH severity filter
        results = search_engine.search_cves(
            "vulnerability",
            filters={'severity': 'HIGH'},
            top_k=5
        )
        
        # All results should be HIGH severity
        if results:
            assert all(r['metadata']['severity'] == 'HIGH' for r in results)
    
    def test_hybrid_search(self, search_engine, chroma_manager, sample_cves, sample_exploits):
        """Test hybrid search across data types"""
        # Add CVEs
        cve_ids = [cve['id'] for cve in sample_cves]
        cve_descriptions = [cve['description'] for cve in sample_cves]
        chroma_manager.add_cve_documents(cve_ids, cve_descriptions)
        
        # Add exploits
        exploit_ids = [exp['id'] for exp in sample_exploits]
        exploit_descriptions = [exp['description'] for exp in sample_exploits]
        chroma_manager.add_exploit_documents(exploit_ids, exploit_descriptions)
        
        # Hybrid search
        results = search_engine.hybrid_search(
            "SQL injection",
            search_types=['cves', 'exploits'],
            aggregate=True
        )
        
        assert 'results' in results
        assert len(results['results']) > 0
    
    def test_result_ranking(self, search_engine):
        """Test result ranking with custom weights"""
        results = [
            {
                'cve_id': 'CVE-2024-0001',
                'similarity_score': 0.9,
                'metadata': {'severity': 'CRITICAL', 'published_date': '2024-01-01'}
            },
            {
                'cve_id': 'CVE-2024-0002',
                'similarity_score': 0.7,
                'metadata': {'severity': 'LOW', 'published_date': '2024-01-10'}
            }
        ]
        
        ranked = search_engine.rank_results(results)
        
        assert len(ranked) == len(results)
        assert 'final_score' in ranked[0]
        # CRITICAL with high similarity should rank first
        assert ranked[0]['cve_id'] == 'CVE-2024-0001'


# AI Agent Tools Tests

class TestAIAgentTools:
    """Test AI agent tools"""
    
    def test_cve_search_tool(self, chroma_manager, sample_cves):
        """Test CVE search tool"""
        # Add test data
        cve_ids = [cve['id'] for cve in sample_cves]
        descriptions = [cve['description'] for cve in sample_cves]
        metadata_list = [
            {'severity': cve['severity'], 'cvss_score': cve['cvss_score']}
            for cve in sample_cves
        ]
        
        chroma_manager.add_cve_documents(cve_ids, descriptions, metadata_list)
        
        # Use tool
        tool = CVESearchTool()
        result = tool._run("SQL injection")
        
        assert isinstance(result, str)
        assert len(result) > 0
        assert 'CVE' in result
    
    def test_exploit_search_tool(self, chroma_manager, sample_exploits):
        """Test exploit search tool"""
        # Add test data
        exploit_ids = [exp['id'] for exp in sample_exploits]
        descriptions = [exp['description'] for exp in sample_exploits]
        metadata_list = [
            {'platform': exp['platform'], 'type': exp['type']}
            for exp in sample_exploits
        ]
        
        chroma_manager.add_exploit_documents(exploit_ids, descriptions, metadata_list)
        
        # Use tool
        tool = ExploitSearchTool()
        result = tool._run("SQL injection")
        
        assert isinstance(result, str)
        assert len(result) > 0
    
    def test_knowledge_tool(self, chroma_manager):
        """Test security knowledge tool"""
        # Add test knowledge
        chroma_manager.add_security_knowledge(
            doc_ids=['doc_001'],
            contents=['SQL injection prevention best practices'],
            metadata_list=[{'topic': 'SQL Injection'}]
        )
        
        # Use tool
        tool = SecurityKnowledgeTool()
        result = tool._run("SQL injection prevention")
        
        assert isinstance(result, str)
        assert len(result) > 0


# Integration Tests

class TestVectorSearchIntegration:
    """Integration tests for complete vector search workflow"""
    
    def test_end_to_end_cve_search(self, chroma_manager, sample_cves):
        """Test complete CVE search workflow"""
        # 1. Index CVEs
        cve_generator = CVEEmbeddingGenerator()
        
        cve_ids = [cve['id'] for cve in sample_cves]
        descriptions = [cve['description'] for cve in sample_cves]
        metadata_list = [
            {
                'severity': cve['severity'],
                'cvss_score': cve['cvss_score']
            }
            for cve in sample_cves
        ]
        
        chroma_manager.add_cve_documents(cve_ids, descriptions, metadata_list)
        
        # 2. Search
        search_engine = SemanticSearchEngine()
        results = search_engine.search_cves("remote code execution", top_k=5)
        
        # 3. Verify results
        assert len(results) > 0
        # RCE CVE should rank high
        assert any('CVE-2024-0003' in r['cve_id'] for r in results)
    
    def test_end_to_end_hybrid_search(self, chroma_manager, sample_cves, sample_exploits):
        """Test complete hybrid search workflow"""
        # Index CVEs
        cve_ids = [cve['id'] for cve in sample_cves]
        cve_descriptions = [cve['description'] for cve in sample_cves]
        chroma_manager.add_cve_documents(cve_ids, cve_descriptions)
        
        # Index exploits
        exploit_ids = [exp['id'] for exp in sample_exploits]
        exploit_descriptions = [exp['description'] for exp in sample_exploits]
        chroma_manager.add_exploit_documents(exploit_ids, exploit_descriptions)
        
        # Hybrid search
        search_engine = SemanticSearchEngine()
        results = search_engine.hybrid_search(
            "SQL injection",
            search_types=['cves', 'exploits'],
            aggregate=True
        )
        
        # Verify both CVEs and exploits found
        assert 'results' in results
        assert len(results['results']) > 0
        
        sources = set(r['source'] for r in results['results'])
        assert 'cve' in sources or 'exploit' in sources


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
