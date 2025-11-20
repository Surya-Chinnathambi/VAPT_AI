"""
Test Configuration and Fixtures
Shared fixtures for all tests
"""
import pytest
import asyncio
from httpx import AsyncClient, ASGITransport
import os
import sqlite3
from typing import Generator
import sys
from pathlib import Path

# Add backend to path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

# Set test database path
os.environ["DB_PATH"] = "test_cybersec_ai.db"

# Import after path setup
from main import app
from utils.database import get_db_connection, init_database


@pytest.fixture(scope="function")
def db_session() -> Generator:
    """
    Create a fresh database for each test
    Cleans up after test completes
    """
    test_db_path = "test_cybersec_ai.db"
    
    # Remove old test database if exists
    if os.path.exists(test_db_path):
        os.remove(test_db_path)
    
    # Initialize test database
    init_database()
    
    # Create connection
    conn = sqlite3.connect(test_db_path)
    conn.row_factory = sqlite3.Row
    
    try:
        yield conn
    finally:
        conn.close()
        # Clean up test database
        if os.path.exists(test_db_path):
            os.remove(test_db_path)

@pytest.fixture(scope="function")
async def client() -> AsyncClient:
    """
    Create an async test client
    """
    # Create async client
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as ac:
        yield ac


@pytest.fixture(scope="session")
def event_loop():
    """
    Create an event loop for async tests
    """
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def test_user_data():
    """
    Sample user data for testing
    """
    return {
        "email": "test@example.com",
        "username": "testuser",
        "password": "SecurePass123!",
        "full_name": "Test User"
    }


@pytest.fixture
def test_scan_data():
    """
    Sample scan data for testing
    """
    return {
        "target": "scanme.nmap.org",
        "scan_type": "quick",
        "async_mode": False
    }


@pytest.fixture
def test_cve_data():
    """
    Sample CVE data for testing
    """
    return {
        "cve_id": "CVE-2024-0001",
        "description": "Test vulnerability",
        "severity": "HIGH",
        "cvss_score": 8.5,
        "published_date": "2024-01-01",
        "affected_products": ["test-product"],
        "references": ["https://example.com/vuln"]
    }


@pytest.fixture
def mock_redis(monkeypatch):
    """
    Mock Redis operations for testing
    """
    class MockRedis:
        def __init__(self):
            self.data = {}
        
        def get(self, key):
            return self.data.get(key)
        
        def set(self, key, value, ex=None):
            self.data[key] = value
            return True
        
        def delete(self, key):
            self.data.pop(key, None)
            return True
        
        def exists(self, key):
            return key in self.data
    
    mock = MockRedis()
    return mock


@pytest.fixture
def mock_celery(monkeypatch):
    """
    Mock Celery tasks for testing
    """
    class MockTask:
        def __init__(self, task_id="test-task-123"):
            self.id = task_id
        
        def get(self):
            return {"status": "completed", "result": "test"}
    
    class MockCelery:
        def delay(self, *args, **kwargs):
            return MockTask()
        
        def apply_async(self, *args, **kwargs):
            return MockTask()
    
    return MockCelery()
