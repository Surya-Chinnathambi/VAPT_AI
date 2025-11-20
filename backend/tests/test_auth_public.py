"""
Authentication Tests - Public endpoints only
Token-protected endpoints (get_current_user) not tested here
"""
import pytest
from httpx import AsyncClient


@pytest.mark.unit
@pytest.mark.asyncio
async def test_register_endpoint_exists(client: AsyncClient):
    """Test that register endpoint exists and returns validation error on empty data"""
    response = await client.post("/api/auth/register", json={})
    # Should return 422 validation error (not 404)
    assert response.status_code in [400, 422]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_login_endpoint_exists(client: AsyncClient):
    """Test that login endpoint exists and returns validation error on empty data"""
    response = await client.post("/api/auth/login", json={})
    # Should return 422 validation error (not 404)
    assert response.status_code in [400, 422]


@pytest.mark.unit
@pytest.mark.asyncio
async def test_sql_injection_protection(client: AsyncClient):
    """Test SQL injection protection in login"""
    response = await client.post("/api/auth/login", json={
        "email": "test@example.com' OR '1'='1",
        "password": "anything"
    })
    # Should not give database error - validation or auth error instead
    assert response.status_code in [400, 401, 422]
    data = response.json()
    assert "sql" not in str(data).lower()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_xss_protection(client: AsyncClient):
    """Test XSS protection in registration"""
    response = await client.post("/api/auth/register", json={
        "email": "<script>alert('xss')</script>@example.com",
        "password": "test123",
        "company": "<img src=x onerror='alert(1)'>"
    })
    # Should validate email format or reject malicious input
    assert response.status_code in [400, 422]
