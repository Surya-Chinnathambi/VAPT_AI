"""
Docker Container Manager for Security Scanning
Manages Docker containers for Nmap and Nikto scans with security controls
"""
import os
import json
import logging
import asyncio
from typing import Dict, Optional, List
from datetime import datetime
import docker
from docker.errors import DockerException, APIError, ContainerError, ImageNotFound


logger = logging.getLogger(__name__)


class DockerScanManager:
    """Manages Docker containers for security scans"""
    
    def __init__(self):
        """Initialize Docker client"""
        try:
            self.client = docker.from_env()
            self.client.ping()
            logger.info("Docker client initialized successfully")
        except DockerException as e:
            logger.error(f"Failed to initialize Docker client: {e}")
            raise
    
    def _ensure_image_exists(self, image_name: str, dockerfile_path: str) -> None:
        """
        Ensure Docker image exists, build if necessary
        
        Args:
            image_name: Name of the Docker image
            dockerfile_path: Path to Dockerfile directory
        """
        try:
            self.client.images.get(image_name)
            logger.info(f"Image {image_name} already exists")
        except ImageNotFound:
            logger.info(f"Building image {image_name}...")
            try:
                image, build_logs = self.client.images.build(
                    path=dockerfile_path,
                    tag=image_name,
                    rm=True,  # Remove intermediate containers
                    forcerm=True  # Always remove intermediate containers
                )
                for log in build_logs:
                    if 'stream' in log:
                        logger.debug(log['stream'].strip())
                logger.info(f"Successfully built image {image_name}")
            except Exception as e:
                logger.error(f"Failed to build image {image_name}: {e}")
                raise
    
    def _get_security_opts(self, scan_type: str) -> Dict:
        """
        Get security options for container
        
        Args:
            scan_type: Type of scan (nmap, nikto)
            
        Returns:
            Dictionary of security options
        """
        base_opts = {
            'security_opt': [
                'no-new-privileges:true',
                'apparmor:docker-default'
            ],
            'cap_drop': ['ALL'],
            'read_only': True,
            'tmpfs': {'/tmp': 'size=100M,mode=1777', '/scans': 'size=100M,mode=1777'},
            'network_mode': 'bridge',
            'mem_limit': '512m',
            'cpu_period': 100000,
            'cpu_quota': 100000,  # 1.0 CPU
            'pids_limit': 100,
        }
        
        if scan_type == 'nmap':
            # Nmap needs NET_RAW capability for raw sockets
            base_opts['cap_add'] = ['NET_RAW']
            
            # Skip seccomp profile for now (causing issues)
            # seccomp_path = os.path.join(
            #     os.path.dirname(__file__),
            #     '../docker/security/seccomp-nmap.json'
            #)
            # if os.path.exists(seccomp_path):
            #     base_opts['security_opt'].append(f'seccomp={seccomp_path}')
        
        elif scan_type == 'nikto':
            # Nikto doesn't need special capabilities
            pass
            # seccomp_path = os.path.join(
            #     os.path.dirname(__file__),
            #     '../docker/security/seccomp-nikto.json'
            # )
            # if os.path.exists(seccomp_path):
            #     base_opts['security_opt'].append(f'seccomp={seccomp_path}')
        
        return base_opts
    
    async def run_nmap_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        scan_type: str = "basic",
        timeout: int = 300
    ) -> Dict:
        """
        Run Nmap scan in Docker container
        
        Args:
            target: Target IP or hostname
            ports: Port specification
            scan_type: Type of scan (basic, stealth, aggressive)
            timeout: Maximum execution time
            
        Returns:
            Dictionary with scan results
        """
        image_name = "cybershield/nmap:latest"
        dockerfile_path = os.path.join(os.path.dirname(__file__), '../docker/nmap')
        
        # Ensure image exists
        self._ensure_image_exists(image_name, dockerfile_path)
        
        # Build command
        command = [
            "--target", target,
            "--scan-type", scan_type,
            "--timeout", str(timeout)
        ]
        
        if ports:
            command.extend(["--ports", ports])
        
        # Get security options
        security_opts = self._get_security_opts('nmap')
        
        # Nmap needs privileged mode for raw sockets on Windows/Docker Desktop
        security_opts['privileged'] = True
        
        # Run container
        try:
            logger.info(f"Starting Nmap scan: target={target}, ports={ports}, type={scan_type}")
            
            container = self.client.containers.run(
                image_name,
                command=command,
                **security_opts,
                detach=True,
                remove=True,  # Auto-remove when done
                environment={
                    'MAX_SCAN_TIME': str(timeout)
                }
            )
            
            # Wait for container to finish (with timeout)
            try:
                result = container.wait(timeout=timeout + 10)
                logs = container.logs().decode('utf-8')
                
                # Parse JSON output
                try:
                    scan_results = json.loads(logs)
                except json.JSONDecodeError:
                    scan_results = {
                        "success": False,
                        "error": "Failed to parse scan output",
                        "raw_output": logs
                    }
                
                logger.info(f"Nmap scan completed: success={scan_results.get('success')}")
                return scan_results
                
            except Exception as e:
                # Kill container if it times out
                try:
                    container.kill()
                except:
                    pass
                logger.error(f"Nmap scan timeout or error: {e}")
                return {
                    "success": False,
                    "error": f"Container execution failed: {str(e)}",
                    "timeout": True
                }
                
        except Exception as e:
            logger.error(f"Failed to run Nmap container: {e}")
            return {
                "success": False,
                "error": f"Container startup failed: {str(e)}"
            }
    
    async def run_nikto_scan(
        self,
        url: str,
        scan_type: str = "basic",
        ssl_check: bool = True,
        timeout: int = 600
    ) -> Dict:
        """
        Run Nikto scan in Docker container
        
        Args:
            url: Target URL
            scan_type: Type of scan (basic, full)
            ssl_check: Whether to verify SSL certificates
            timeout: Maximum execution time
            
        Returns:
            Dictionary with scan results
        """
        image_name = "cybershield/nikto:latest"
        dockerfile_path = os.path.join(os.path.dirname(__file__), '../docker/nikto')
        
        # Ensure image exists
        self._ensure_image_exists(image_name, dockerfile_path)
        
        # Build command
        command = [
            "--url", url,
            "--scan-type", scan_type,
            "--timeout", str(timeout)
        ]
        
        if not ssl_check:
            command.append("--no-ssl-check")
        
        # Get security options
        security_opts = self._get_security_opts('nikto')
        security_opts['mem_limit'] = '512m'  # Nikto may need more memory
        
        # Run container
        try:
            logger.info(f"Starting Nikto scan: url={url}, type={scan_type}")
            
            container = self.client.containers.run(
                image_name,
                command=command,
                **security_opts,
                detach=True,
                remove=True,
                environment={
                    'MAX_SCAN_TIME': str(timeout)
                }
            )
            
            # Wait for container to finish
            try:
                result = container.wait(timeout=timeout + 10)
                logs = container.logs().decode('utf-8')
                
                # Parse JSON output
                try:
                    scan_results = json.loads(logs)
                except json.JSONDecodeError:
                    scan_results = {
                        "success": False,
                        "error": "Failed to parse scan output",
                        "raw_output": logs
                    }
                
                logger.info(f"Nikto scan completed: success={scan_results.get('success')}")
                return scan_results
                
            except Exception as e:
                try:
                    container.kill()
                except:
                    pass
                logger.error(f"Nikto scan timeout or error: {e}")
                return {
                    "success": False,
                    "error": f"Container execution failed: {str(e)}",
                    "timeout": True
                }
                
        except Exception as e:
            logger.error(f"Failed to run Nikto container: {e}")
            return {
                "success": False,
                "error": f"Container startup failed: {str(e)}"
            }
    
    async def run_generic_tool(
        self,
        image: str,
        command: str,
        timeout: int = 300,
        environment: Optional[Dict[str, str]] = None,
        volumes: Optional[Dict[str, Dict[str, str]]] = None
    ) -> Dict:
        """
        Run a generic security tool in Docker container
        
        Args:
            image: Docker image name (e.g., "projectdiscovery/nuclei:latest")
            command: Command to run inside container
            timeout: Maximum execution time in seconds
            environment: Environment variables
            volumes: Volume mounts
            
        Returns:
            Dictionary with execution results
        """
        try:
            logger.info(f"Running generic tool: image={image}, command={command}")
            
            # Try to pull image if it doesn't exist
            try:
                self.client.images.get(image)
            except ImageNotFound:
                logger.info(f"Pulling image {image}...")
                try:
                    self.client.images.pull(image)
                    logger.info(f"Successfully pulled {image}")
                except Exception as e:
                    logger.error(f"Failed to pull image {image}: {e}")
                    return {
                        "success": False,
                        "error": f"Failed to pull image: {str(e)}"
                    }
            
            # Basic security options for generic tools
            container_opts = {
                'security_opt': ['no-new-privileges:true'],
                'cap_drop': ['ALL'],
                'network_mode': 'bridge',
                'mem_limit': '1g',
                'cpu_period': 100000,
                'cpu_quota': 150000,  # 1.5 CPU
                'pids_limit': 200,
                'remove': True,  # Auto-remove after completion
                'detach': False,
                'stdout': True,
                'stderr': True,
            }
            
            if environment:
                container_opts['environment'] = environment
            
            if volumes:
                container_opts['volumes'] = volumes
            
            # Run container
            try:
                output = self.client.containers.run(
                    image,
                    command,
                    **container_opts
                )
                
                decoded_output = output.decode('utf-8') if isinstance(output, bytes) else str(output)
                
                return {
                    "success": True,
                    "output": decoded_output,
                    "image": image,
                    "command": command
                }
                
            except ContainerError as e:
                logger.error(f"Container execution error: {e}")
                return {
                    "success": False,
                    "error": f"Container execution failed: {str(e)}",
                    "exit_code": e.exit_status,
                    "output": e.stderr.decode('utf-8') if e.stderr else ""
                }
            except Exception as e:
                logger.error(f"Unexpected container error: {e}")
                return {
                    "success": False,
                    "error": f"Container error: {str(e)}"
                }
                
        except Exception as e:
            logger.error(f"Failed to run generic tool: {e}")
            return {
                "success": False,
                "error": f"Tool execution failed: {str(e)}"
            }
    
    def cleanup_old_containers(self, max_age_hours: int = 24) -> int:
        """
        Clean up old/stopped scan containers
        
        Args:
            max_age_hours: Maximum age in hours
            
        Returns:
            Number of containers cleaned up
        """
        count = 0
        try:
            containers = self.client.containers.list(
                all=True,
                filters={'status': 'exited'}
            )
            
            for container in containers:
                # Check if it's a scan container
                if any(name in container.name for name in ['nmap', 'nikto', 'cybershield']):
                    try:
                        container.remove()
                        count += 1
                    except Exception as e:
                        logger.warning(f"Failed to remove container {container.name}: {e}")
            
            logger.info(f"Cleaned up {count} old scan containers")
            return count
            
        except Exception as e:
            logger.error(f"Failed to cleanup containers: {e}")
            return 0
    
    def get_container_stats(self) -> Dict:
        """
        Get statistics about scan containers
        
        Returns:
            Dictionary with container statistics
        """
        try:
            all_containers = self.client.containers.list(all=True)
            scan_containers = [c for c in all_containers if any(
                name in c.name for name in ['nmap', 'nikto', 'cybershield']
            )]
            
            stats = {
                'total_containers': len(scan_containers),
                'running': len([c for c in scan_containers if c.status == 'running']),
                'exited': len([c for c in scan_containers if c.status == 'exited']),
                'containers': []
            }
            
            for container in scan_containers:
                stats['containers'].append({
                    'name': container.name,
                    'status': container.status,
                    'image': container.image.tags[0] if container.image.tags else 'unknown'
                })
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get container stats: {e}")
            return {'error': str(e)}


# Global singleton
_docker_manager: Optional[DockerScanManager] = None


def get_docker_manager() -> DockerScanManager:
    """Get or create Docker manager singleton"""
    global _docker_manager
    if _docker_manager is None:
        _docker_manager = DockerScanManager()
    return _docker_manager
