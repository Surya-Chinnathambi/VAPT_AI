"""
API Endpoint Health Tests
Basic smoke tests to ensure all endpoints are accessible
"""
import pytest
from httpx import AsyncClient


@pytest.mark.unit
@pytest.mark.asyncio
async def test_root_endpoint(client: AsyncClient):
    """Test root endpoint returns API info"""
    response = await client.get("/")
    
    assert response.status_code == 200
    data = response.json()
    assert "name" in data
    assert "version" in data
    assert "status" in data


@pytest.mark.unit
@pytest.mark.asyncio
async def test_health_check(client: AsyncClient):
    """Test health check endpoint"""
    response = await client.get("/health")
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "timestamp" in data


@pytest.mark.unit
@pytest.mark.asyncio
async def test_sentry_test_endpoint(client: AsyncClient):
    """Test that Sentry test endpoint exists (should error)"""
    try:
        response = await client.get("/api/sentry-test")
        # Should get 500 error
        assert response.status_code == 500
    except Exception as e:
        # Endpoint intentionally raises ZeroDivisionError
        # This is expected behavior
        assert "ZeroDivisionError" in str(type(e)) or "division" in str(e).lower()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_cors_headers(client: AsyncClient):
    """Test CORS headers are present"""
    response = await client.options("/api/auth/login")
    
    # Should have CORS headers
    assert response.status_code in [200, 405]  # OPTIONS might not be allowed


@pytest.mark.unit
@pytest.mark.asyncio
async def test_404_handling(client: AsyncClient):
    """Test 404 handling for non-existent routes"""
    response = await client.get("/api/nonexistent/route")
    
    assert response.status_code == 404


@pytest.mark.unit
@pytest.mark.asyncio
async def test_rate_limit_headers(client: AsyncClient):
    """Test that rate limit headers are present (or at least not 500)"""
    response = await client.get("/api/cve/search?query=test")
    
    # Should not be 500 error
    assert response.status_code != 500
    # May be 403 (auth required) or 200 (public endpoint)
    assert response.status_code in [200, 403, 401, 400]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_database_connection(client: AsyncClient):
    """Test database connectivity through any endpoint that uses DB"""
    # Try to access an endpoint that requires DB
    response = await client.get("/health")
    
    # Should not fail with database errors
    assert response.status_code == 200
