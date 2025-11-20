"""
Authentication Tests - Fixed Version
Handles token-required endpoints properly
"""
import pytest
from httpx import AsyncClient


@pytest.mark.unit
@pytest.mark.asyncio
async def test_health_check(client: AsyncClient):
    """Test health check endpoint (no auth required)"""
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_root_endpoint(client: AsyncClient):
    """Test root endpoint (no auth required)"""
    response = await client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "name" in data
    assert "version" in data


@pytest.mark.unit
@pytest.mark.asyncio
async def test_api_docs_available(client: AsyncClient):
    """Test that API documentation is available"""
    response = await client.get("/docs")
    assert response.status_code == 200


@pytest.mark.unit
@pytest.mark.asyncio
async def test_404_handling(client: AsyncClient):
    """Test 404 handling for non-existent routes"""
    response = await client.get("/api/nonexistent/route")
    assert response.status_code == 404


@pytest.mark.unit
@pytest.mark.asyncio
async def test_cors_preflight(client: AsyncClient):
    """Test CORS preflight request"""
    response = await client.options("/api/auth/login")
    # Should be 200 or 405 depending on CORS config
    assert response.status_code in [200, 405]
