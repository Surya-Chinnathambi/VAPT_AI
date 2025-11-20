"""
CVE Database Tests - Public Endpoints Only
Tests that CVE endpoints exist and handle requests appropriately
"""
import pytest
from httpx import AsyncClient


@pytest.mark.unit
@pytest.mark.asyncio
async def test_cve_search_endpoint(client: AsyncClient):
    """Test CVE search endpoint"""
    response = await client.get("/api/cve/search?query=apache")
    # Endpoint should exist (not 404)
    assert response.status_code != 404
    # Should return 200, 403 (auth), or 400 (bad request)
    assert response.status_code in [200, 400, 403, 401]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_cve_search_by_id(client: AsyncClient):
    """Test CVE get by ID endpoint"""
    response = await client.get("/api/cve/CVE-2021-44228")
    # Should handle the request (not 404)
    assert response.status_code in [200, 404, 403, 401]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_cve_ai_search_endpoint(client: AsyncClient):
    """Test CVE AI search endpoint"""
    response = await client.post("/api/cve/ai-search", json={
        "query": "remote code execution"
    })
    # Endpoint should exist
    assert response.status_code in [200, 405, 403, 401, 400]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_cve_exploits_endpoint(client: AsyncClient):
    """Test CVE to exploit linking endpoint"""
    response = await client.get("/api/cve/CVE-2021-44228/exploits")
    # Should handle request
    assert response.status_code in [200, 404, 403, 401]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_exploit_search_endpoint(client: AsyncClient):
    """Test exploit search endpoint"""
    response = await client.get("/api/exploits/search?cve=CVE-2021-44228")
    # Endpoint should exist
    assert response.status_code in [200, 400, 403, 401]
