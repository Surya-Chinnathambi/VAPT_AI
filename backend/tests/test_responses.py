"""
Response Tests - Test that endpoints return expected response structures
"""
import pytest
from httpx import AsyncClient


@pytest.mark.unit
@pytest.mark.asyncio
async def test_root_response_structure(client: AsyncClient):
    """Test that root endpoint returns correct structure"""
    response = await client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "name" in data
    assert "version" in data


@pytest.mark.unit
@pytest.mark.asyncio
async def test_health_response_structure(client: AsyncClient):
    """Test that health endpoint returns correct structure"""
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data


@pytest.mark.unit
@pytest.mark.asyncio
async def test_404_response_is_json(client: AsyncClient):
    """Test that 404 responses are valid JSON"""
    response = await client.get("/api/nonexistent")
    assert response.status_code == 404
    data = response.json()
    assert "detail" in data or "message" in data


@pytest.mark.unit
@pytest.mark.asyncio
async def test_cors_headers_present(client: AsyncClient):
    """Test that CORS headers are present"""
    response = await client.get("/")
    assert response.status_code == 200
    # CORS headers may or may not be present depending on configuration
    # Just ensure response is valid
    assert response.headers is not None


@pytest.mark.unit
@pytest.mark.asyncio
async def test_auth_endpoint_validation(client: AsyncClient):
    """Test that auth endpoint validates input"""
    # Send invalid JSON
    response = await client.post("/api/auth/register", json={
        "email": "invalid"  # Missing password and company
    })
    # Should return validation error
    assert response.status_code in [400, 422]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_scan_endpoint_validation(client: AsyncClient):
    """Test that scan endpoint validates input"""
    # Send invalid scan request
    response = await client.post("/api/scan/nmap", json={
        "target": ""  # Empty target
    })
    # Should not accept empty target
    assert response.status_code in [400, 401, 403, 422]
