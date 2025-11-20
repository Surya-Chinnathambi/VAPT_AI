"""
Docker Sandboxing Tests - Week 5-6
Tests for Docker container execution, security policies, and resource limits
"""
import pytest
import asyncio
import os
import json
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime


# Test Docker Manager
class TestDockerManager:
    """Test Docker container management"""
    
    @pytest.fixture
    def mock_docker_client(self):
        """Mock Docker client"""
        with patch('docker.from_env') as mock:
            client = MagicMock()
            client.ping.return_value = True
            mock.return_value = client
            yield client
    
    def test_docker_manager_initialization(self, mock_docker_client):
        """Test Docker manager initializes correctly"""
        from core.docker_manager import DockerScanManager
        
        manager = DockerScanManager()
        assert manager.client is not None
        mock_docker_client.ping.assert_called_once()
    
    def test_docker_manager_singleton(self):
        """Test Docker manager singleton pattern"""
        from core.docker_manager import get_docker_manager
        
        with patch('docker.from_env'):
            manager1 = get_docker_manager()
            manager2 = get_docker_manager()
            assert manager1 is manager2
    
    def test_security_options_nmap(self, mock_docker_client):
        """Test security options for Nmap container"""
        from core.docker_manager import DockerScanManager
        
        manager = DockerScanManager()
        opts = manager._get_security_opts('nmap')
        
        # Verify security restrictions
        assert 'no-new-privileges:true' in opts['security_opt']
        assert 'apparmor:docker-default' in opts['security_opt']
        assert 'ALL' in opts['cap_drop']
        assert 'NET_RAW' in opts['cap_add']  # Required for nmap
        assert opts['read_only'] is True
        assert opts['mem_limit'] == '512m'
        assert opts['pids_limit'] == 100
    
    def test_security_options_nikto(self, mock_docker_client):
        """Test security options for Nikto container"""
        from core.docker_manager import DockerScanManager
        
        manager = DockerScanManager()
        opts = manager._get_security_opts('nikto')
        
        # Verify security restrictions
        assert 'no-new-privileges:true' in opts['security_opt']
        assert 'ALL' in opts['cap_drop']
        assert 'cap_add' not in opts  # Nikto doesn't need special capabilities
        assert opts['read_only'] is True
        assert opts['mem_limit'] == '512m'
    
    @pytest.mark.asyncio
    async def test_nmap_scan_execution(self, mock_docker_client):
        """Test Nmap scan execution in container"""
        from core.docker_manager import DockerScanManager
        
        # Mock container
        mock_container = MagicMock()
        mock_container.wait.return_value = {'StatusCode': 0}
        mock_container.logs.return_value = b'{"success": true, "scan_completed": true}'
        
        mock_docker_client.containers.run.return_value = mock_container
        mock_docker_client.images.get.return_value = MagicMock()
        
        manager = DockerScanManager()
        result = await manager.run_nmap_scan(
            target="192.168.1.1",
            ports="80,443",
            scan_type="basic",
            timeout=300
        )
        
        assert result['success'] is True
        assert result['scan_completed'] is True
        
        # Verify container was run with correct parameters
        mock_docker_client.containers.run.assert_called_once()
        call_kwargs = mock_docker_client.containers.run.call_args[1]
        assert call_kwargs['detach'] is True
        assert call_kwargs['remove'] is True
        assert 'security_opt' in call_kwargs
    
    @pytest.mark.asyncio
    async def test_nmap_scan_timeout(self, mock_docker_client):
        """Test Nmap scan timeout handling"""
        from core.docker_manager import DockerScanManager
        
        # Mock timeout
        mock_container = MagicMock()
        mock_container.wait.side_effect = Exception("Timeout")
        
        mock_docker_client.containers.run.return_value = mock_container
        mock_docker_client.images.get.return_value = MagicMock()
        
        manager = DockerScanManager()
        result = await manager.run_nmap_scan(
            target="192.168.1.1",
            timeout=1
        )
        
        assert result['success'] is False
        assert 'timeout' in result or 'error' in result
        mock_container.kill.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_nikto_scan_execution(self, mock_docker_client):
        """Test Nikto scan execution in container"""
        from core.docker_manager import DockerScanManager
        
        # Mock container
        mock_container = MagicMock()
        mock_container.wait.return_value = {'StatusCode': 0}
        mock_container.logs.return_value = b'{"success": true, "findings_count": 5}'
        
        mock_docker_client.containers.run.return_value = mock_container
        mock_docker_client.images.get.return_value = MagicMock()
        
        manager = DockerScanManager()
        result = await manager.run_nikto_scan(
            url="https://example.com",
            scan_type="basic",
            timeout=600
        )
        
        assert result['success'] is True
        assert result['findings_count'] == 5
    
    def test_cleanup_old_containers(self, mock_docker_client):
        """Test cleanup of old scan containers"""
        from core.docker_manager import DockerScanManager
        
        # Mock old containers
        mock_container1 = MagicMock()
        mock_container1.name = "cybershield_nmap_old"
        mock_container2 = MagicMock()
        mock_container2.name = "cybershield_nikto_old"
        mock_container3 = MagicMock()
        mock_container3.name = "other_container"
        
        mock_docker_client.containers.list.return_value = [
            mock_container1, mock_container2, mock_container3
        ]
        
        manager = DockerScanManager()
        count = manager.cleanup_old_containers()
        
        # Should clean up 2 cybershield containers, not the other one
        assert count == 2
        mock_container1.remove.assert_called_once()
        mock_container2.remove.assert_called_once()
        mock_container3.remove.assert_not_called()
    
    def test_container_stats(self, mock_docker_client):
        """Test getting container statistics"""
        from core.docker_manager import DockerScanManager
        
        # Mock containers
        mock_image = MagicMock()
        mock_image.tags = ["cybershield/nmap:latest"]
        
        mock_container = MagicMock()
        mock_container.name = "cybershield_nmap_1"
        mock_container.status = "running"
        mock_container.image = mock_image
        
        mock_docker_client.containers.list.return_value = [mock_container]
        
        manager = DockerScanManager()
        stats = manager.get_container_stats()
        
        assert stats['total_containers'] == 1
        assert stats['running'] == 1
        assert len(stats['containers']) == 1
        assert stats['containers'][0]['name'] == "cybershield_nmap_1"


# Test Service Integration
class TestScanServiceIntegration:
    """Test scan service integration with Docker"""
    
    @pytest.mark.asyncio
    async def test_port_scanner_docker_integration(self):
        """Test port scanner with Docker enabled"""
        from services import port_scanner_service
        
        with patch.object(port_scanner_service, 'get_docker_manager') as mock_manager_fn:
            mock_manager = MagicMock()
            
            # Create async mock for run_nmap_scan
            async def mock_run_nmap_scan(*args, **kwargs):
                return {
                    'success': True,
                    'scan_completed': True
                }
            
            mock_manager.run_nmap_scan = mock_run_nmap_scan
            mock_manager_fn.return_value = mock_manager
            
            result = await port_scanner_service.perform_port_scan_docker(
                host="192.168.1.1",
                ports=[80, 443],
                scan_type="common"
            )
            
            assert result['scan_method'] == 'docker_nmap'
            assert 'host' in result
            assert 'scan_time' in result
    
    @pytest.mark.asyncio
    async def test_web_scanner_docker_integration(self):
        """Test web scanner with Docker enabled"""
        from services import web_scanner_service
        
        with patch.object(web_scanner_service, 'get_docker_manager') as mock_manager_fn:
            mock_manager = MagicMock()
            
            # Create async mock for run_nikto_scan
            async def mock_run_nikto_scan(*args, **kwargs):
                return {
                    'success': True,
                    'vulnerabilities': ['Finding 1', 'Finding 2'],
                    'findings_count': 2
                }
            
            mock_manager.run_nikto_scan = mock_run_nikto_scan
            mock_manager_fn.return_value = mock_manager
            
            # Mock the native check functions to avoid network calls
            with patch.object(web_scanner_service, 'check_ssl_certificate', return_value={}):
                with patch.object(web_scanner_service, 'check_security_headers', return_value={'missing_headers': []}):
                    result = await web_scanner_service.perform_web_scan_docker(
                        url="https://example.com",
                        options={'scan_ssl': True, 'scan_headers': True, 'scan_paths': True}
                    )
            
            assert result['scan_method'] == 'docker_nikto'
            assert result['findings_count'] == 2
            assert len(result['nikto_findings']) == 2
    
    def test_port_scanner_fallback(self):
        """Test port scanner falls back to native on Docker error"""
        from services.port_scanner_service import perform_port_scan
        
        with patch('services.port_scanner_service.DOCKER_AVAILABLE', False):
            result = perform_port_scan(
                host="127.0.0.1",
                ports=[80],
                scan_type="common"
            )
            
            # Should use native method
            assert result['scan_method'] == 'native_python'
    
    def test_web_scanner_fallback(self):
        """Test web scanner falls back to native on Docker error"""
        from services.web_scanner_service import perform_web_scan
        
        with patch('services.web_scanner_service.DOCKER_AVAILABLE', False):
            result = perform_web_scan(
                url="http://localhost",
                options={'scan_ssl': False, 'scan_headers': True, 'scan_paths': False}
            )
            
            # Should use native method
            assert result['scan_method'] == 'native_python'


# Test Scan Executors
class TestScanExecutors:
    """Test Docker container scan executors"""
    
    def test_nmap_executor_validation(self):
        """Test Nmap executor input validation"""
        import sys
        import os
        
        # Add docker/nmap to path
        nmap_path = os.path.join(
            os.path.dirname(__file__),
            '../docker/nmap'
        )
        sys.path.insert(0, nmap_path)
        
        try:
            from scan_executor import validate_target
            
            # Valid targets
            assert validate_target("192.168.1.1")
            assert validate_target("example.com")
            assert validate_target("192.168.1.0/24")
            
            # Invalid targets
            with pytest.raises(ValueError):
                validate_target("192.168.1.1; rm -rf /")
            
            with pytest.raises(ValueError):
                validate_target("$(whoami)")
            
            with pytest.raises(ValueError):
                validate_target("192.168.1.1|nc -e /bin/sh")
        finally:
            sys.path.pop(0)
    
    def test_nmap_executor_port_validation(self):
        """Test Nmap executor port validation"""
        import sys
        import os
        
        nmap_path = os.path.join(
            os.path.dirname(__file__),
            '../docker/nmap'
        )
        sys.path.insert(0, nmap_path)
        
        try:
            from scan_executor import validate_ports
            
            # Valid port specifications
            assert validate_ports("80")
            assert validate_ports("80,443")
            assert validate_ports("1-1000")
            assert validate_ports("80,443,8000-9000")
            
            # Invalid specifications
            with pytest.raises(ValueError):
                validate_ports("80; rm -rf /")
            
            with pytest.raises(ValueError):
                validate_ports("80|443")
        finally:
            sys.path.pop(0)
    
    def test_nikto_executor_url_validation(self):
        """Test Nikto executor URL validation"""
        import sys
        import os
        
        nikto_path = os.path.join(
            os.path.dirname(__file__),
            '../docker/nikto'
        )
        sys.path.insert(0, nikto_path)
        
        try:
            from web_scan_executor import validate_url
            
            # Valid URLs
            assert validate_url("http://example.com")
            assert validate_url("https://example.com")
            assert validate_url("https://sub.example.com:8080/path")
            
            # Invalid URLs (SSRF prevention)
            with pytest.raises(ValueError):
                validate_url("http://localhost")
            
            with pytest.raises(ValueError):
                validate_url("http://127.0.0.1")
            
            with pytest.raises(ValueError):
                validate_url("http://192.168.1.1")  # Private IP
            
            with pytest.raises(ValueError):
                validate_url("file:///etc/passwd")
            
            with pytest.raises(ValueError):
                validate_url("http://example.com; rm -rf /")
        finally:
            sys.path.pop(0)


# Test Resource Limits
class TestResourceLimits:
    """Test Docker resource limits and security policies"""
    
    def test_memory_limit_enforcement(self, mock_docker_client=None):
        """Test memory limit is enforced"""
        from core.docker_manager import DockerScanManager
        
        with patch('docker.from_env') as mock_client_fn:
            mock_client = MagicMock()
            mock_client.ping.return_value = True
            mock_client_fn.return_value = mock_client
            
            manager = DockerScanManager()
            opts = manager._get_security_opts('nmap')
            
            assert opts['mem_limit'] == '512m'
    
    def test_cpu_limit_enforcement(self):
        """Test CPU limit is enforced"""
        from core.docker_manager import DockerScanManager
        
        with patch('docker.from_env'):
            manager = DockerScanManager()
            opts = manager._get_security_opts('nmap')
            
            # 1.0 CPU = 100000 quota / 100000 period
            assert opts['cpu_period'] == 100000
            assert opts['cpu_quota'] == 100000
    
    def test_process_limit_enforcement(self):
        """Test process/PID limit is enforced"""
        from core.docker_manager import DockerScanManager
        
        with patch('docker.from_env'):
            manager = DockerScanManager()
            opts = manager._get_security_opts('nmap')
            
            assert opts['pids_limit'] == 100
    
    def test_readonly_filesystem(self):
        """Test read-only filesystem is enforced"""
        from core.docker_manager import DockerScanManager
        
        with patch('docker.from_env'):
            manager = DockerScanManager()
            opts = manager._get_security_opts('nmap')
            
            assert opts['read_only'] is True
            assert '/tmp' in opts['tmpfs']
            assert '/scans' in opts['tmpfs']
    
    def test_capability_dropping(self):
        """Test all capabilities are dropped (except NET_RAW for nmap)"""
        from core.docker_manager import DockerScanManager
        
        with patch('docker.from_env'):
            manager = DockerScanManager()
            
            # Nmap needs NET_RAW
            nmap_opts = manager._get_security_opts('nmap')
            assert 'ALL' in nmap_opts['cap_drop']
            assert 'NET_RAW' in nmap_opts['cap_add']
            
            # Nikto doesn't need any capabilities
            nikto_opts = manager._get_security_opts('nikto')
            assert 'ALL' in nikto_opts['cap_drop']
            assert 'cap_add' not in nikto_opts


# Test Environment Configuration
class TestEnvironmentConfiguration:
    """Test environment-based configuration"""
    
    def test_docker_scans_enabled(self):
        """Test Docker scans can be enabled via environment"""
        with patch.dict(os.environ, {'USE_DOCKER_SCANS': 'true'}):
            # Re-import to get new environment value
            import importlib
            import services.port_scanner_service as pss
            importlib.reload(pss)
            
            assert pss.DOCKER_AVAILABLE is True
    
    def test_docker_scans_disabled(self):
        """Test Docker scans can be disabled via environment"""
        with patch.dict(os.environ, {'USE_DOCKER_SCANS': 'false'}):
            import importlib
            import services.port_scanner_service as pss
            importlib.reload(pss)
            
            assert pss.DOCKER_AVAILABLE is False


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
