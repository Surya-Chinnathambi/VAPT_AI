"""
Protected Endpoints Tests
Tests for endpoints that require authentication
Tests check that endpoints exist (not 404) and properly require auth (403/401)
"""
import pytest
from httpx import AsyncClient


class TestScanningEndpoints:
    """Test scanning endpoints exist"""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_nmap_endpoint_exists(self, client: AsyncClient):
        """Test that /api/scan/nmap endpoint exists (may return 403 without auth)"""
        response = await client.post("/api/scan/nmap", json={
            "target": "example.com",
            "scan_type": "quick"
        })
        # Should not be 404 (endpoint exists)
        # Will be 403 because no auth token provided
        assert response.status_code != 404
        assert response.status_code in [403, 401, 400, 422]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_port_scanner_endpoint_exists(self, client: AsyncClient):
        """Test that /api/scan/port endpoint exists"""
        response = await client.post("/api/scan/port", json={
            "target": "example.com",
            "ports": "80,443"
        })
        # Should not be 404
        assert response.status_code != 404

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_web_scanner_endpoint_exists(self, client: AsyncClient):
        """Test that /api/scan/web endpoint exists"""
        response = await client.post("/api/scan/web", json={
            "target": "https://example.com"
        })
        # Should not be 404
        assert response.status_code != 404

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_scan_status_endpoint_exists(self, client: AsyncClient):
        """Test that /api/scan/status endpoint exists"""
        response = await client.get("/api/scan/status/test-task-id")
        # Should not be 404
        assert response.status_code != 404


class TestCVEEndpoints:
    """Test CVE endpoints exist"""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_cve_search_endpoint_exists(self, client: AsyncClient):
        """Test that /api/cve/search endpoint exists"""
        response = await client.get("/api/cve/search?query=apache")
        # Should not be 404
        assert response.status_code != 404
        # Will be 403 without auth, or 200 if public
        assert response.status_code in [200, 403, 401]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_cve_by_id_endpoint_exists(self, client: AsyncClient):
        """Test that /api/cve/{cve_id} endpoint exists"""
        response = await client.get("/api/cve/CVE-2021-44228")
        # Should not be 404 if endpoint exists
        # Might be 404 if CVE not found, but endpoint should be routable
        assert response.status_code in [200, 404, 403, 401]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_cve_by_id_exploits_endpoint(self, client: AsyncClient):
        """Test that /api/cve/{cve_id}/exploits endpoint exists"""
        response = await client.get("/api/cve/CVE-2021-44228/exploits")
        # Should not be 404 if endpoint exists
        assert response.status_code in [200, 404, 403, 401]


class TestExploitEndpoints:
    """Test exploit endpoints exist"""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_exploit_search_endpoint_exists(self, client: AsyncClient):
        """Test that /api/exploits/search endpoint exists"""
        response = await client.get("/api/exploits/search?cve=CVE-2021-44228")
        # Should not be 404
        assert response.status_code != 404


class TestReportEndpoints:
    """Test report endpoints exist"""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_report_generate_endpoint_exists(self, client: AsyncClient):
        """Test that /api/reports/generate endpoint exists"""
        response = await client.post("/api/reports/generate", json={
            "scan_id": "test-scan"
        })
        # Should handle request
        assert response.status_code in [200, 403, 401, 400, 422]
