"""
Real-time VAPT Scanner with WebSocket streaming
Executes Docker-based security scans with live result updates
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException
from typing import Dict, List, Optional
import asyncio
import json
import docker
import logging
from datetime import datetime

from routers.auth import verify_token
from database.connection import create_scan, update_scan_status

logger = logging.getLogger(__name__)
router = APIRouter()

# Docker client
try:
    docker_client = docker.from_env()
    DOCKER_AVAILABLE = True
except Exception as e:
    logger.warning(f"Docker not available: {e}")
    DOCKER_AVAILABLE = False


class ScanManager:
    """Manages active WebSocket scan connections"""
    
    def __init__(self):
        self.active_scans: Dict[str, WebSocket] = {}
    
    async def connect(self, scan_id: str, websocket: WebSocket):
        """Register new scan connection"""
        await websocket.accept()
        self.active_scans[scan_id] = websocket
        logger.info(f"WebSocket connected for scan {scan_id}")
    
    def disconnect(self, scan_id: str):
        """Remove scan connection"""
        if scan_id in self.active_scans:
            del self.active_scans[scan_id]
            logger.info(f"WebSocket disconnected for scan {scan_id}")
    
    async def send_update(self, scan_id: str, message: dict):
        """Send real-time update to client"""
        if scan_id in self.active_scans:
            try:
                await self.active_scans[scan_id].send_json(message)
            except Exception as e:
                logger.error(f"Failed to send update for scan {scan_id}: {e}")
                self.disconnect(scan_id)


scan_manager = ScanManager()


async def stream_docker_logs(container, scan_id: str, scan_type: str):
    """
    Stream Docker container logs in real-time
    
    Args:
        container: Docker container object
        scan_id: Unique scan identifier
        scan_type: Type of scan (nmap, nikto, etc.)
    """
    vulnerabilities = []
    open_ports = []
    findings = []
    
    try:
        # Send initial status
        await scan_manager.send_update(scan_id, {
            "type": "status",
            "status": "running",
            "message": f"Starting {scan_type} scan...",
            "timestamp": datetime.now().isoformat()
        })
        
        # Stream container logs
        for log_line in container.logs(stream=True, follow=True):
            try:
                log_text = log_line.decode('utf-8').strip()
                
                if not log_text:
                    continue
                
                # Send raw log
                await scan_manager.send_update(scan_id, {
                    "type": "log",
                    "message": log_text,
                    "timestamp": datetime.now().isoformat()
                })
                
                # Parse scan results in real-time
                if scan_type == "nmap":
                    # Parse Nmap output for open ports
                    if "/tcp" in log_text or "/udp" in log_text:
                        port_info = parse_nmap_port(log_text)
                        if port_info:
                            open_ports.append(port_info)
                            await scan_manager.send_update(scan_id, {
                                "type": "port_found",
                                "data": port_info,
                                "total_ports": len(open_ports),
                                "timestamp": datetime.now().isoformat()
                            })
                    
                    # Detect vulnerabilities
                    if any(keyword in log_text.lower() for keyword in ['vuln', 'cve-', 'exploit', 'vulnerable']):
                        vuln_info = parse_nmap_vulnerability(log_text)
                        if vuln_info:
                            vulnerabilities.append(vuln_info)
                            await scan_manager.send_update(scan_id, {
                                "type": "vulnerability_found",
                                "data": vuln_info,
                                "total_vulns": len(vulnerabilities),
                                "timestamp": datetime.now().isoformat()
                            })
                
                elif scan_type == "nikto":
                    # Parse Nikto findings
                    if "+" in log_text and ("OSVDB" in log_text or "found" in log_text.lower()):
                        finding = parse_nikto_finding(log_text)
                        if finding:
                            findings.append(finding)
                            await scan_manager.send_update(scan_id, {
                                "type": "finding",
                                "data": finding,
                                "total_findings": len(findings),
                                "timestamp": datetime.now().isoformat()
                            })
                
                elif scan_type == "sqlmap":
                    # Parse SQLMap injection points
                    if "vulnerable" in log_text.lower() or "injection" in log_text.lower():
                        vuln_info = parse_sqlmap_finding(log_text)
                        if vuln_info:
                            vulnerabilities.append(vuln_info)
                            await scan_manager.send_update(scan_id, {
                                "type": "sql_injection",
                                "data": vuln_info,
                                "total_vulns": len(vulnerabilities),
                                "timestamp": datetime.now().isoformat()
                            })
                
                # Progress updates
                await asyncio.sleep(0.01)  # Prevent flooding
                
            except Exception as e:
                logger.error(f"Error processing log line: {e}")
                continue
        
        # Wait for container to finish
        result = container.wait()
        exit_code = result.get('StatusCode', -1)
        
        # Collect final results
        final_results = {
            "scan_type": scan_type,
            "exit_code": exit_code,
            "open_ports": open_ports,
            "vulnerabilities": vulnerabilities,
            "findings": findings,
            "total_open_ports": len(open_ports),
            "total_vulnerabilities": len(vulnerabilities),
            "total_findings": len(findings)
        }
        
        # Send completion status
        if exit_code == 0:
            await scan_manager.send_update(scan_id, {
                "type": "completed",
                "status": "success",
                "results": final_results,
                "timestamp": datetime.now().isoformat()
            })
            
            # Update database
            update_scan_status(
                scan_id=int(scan_id.split('-')[0]) if '-' in scan_id else int(scan_id),
                status="completed",
                raw_output=json.dumps(final_results),
                summary=f"{scan_type} scan: {len(vulnerabilities)} vulnerabilities, {len(open_ports)} open ports",
                vulnerabilities_found=len(vulnerabilities) + len(findings),
                risk_level=calculate_risk_level(vulnerabilities, findings)
            )
        else:
            await scan_manager.send_update(scan_id, {
                "type": "failed",
                "status": "error",
                "message": f"Scan exited with code {exit_code}",
                "timestamp": datetime.now().isoformat()
            })
        
        # Cleanup
        try:
            container.remove(force=True)
        except:
            pass
            
    except Exception as e:
        logger.error(f"Error streaming logs: {e}")
        await scan_manager.send_update(scan_id, {
            "type": "error",
            "message": str(e),
            "timestamp": datetime.now().isoformat()
        })


def parse_nmap_port(log_line: str) -> Optional[Dict]:
    """Parse Nmap port information from log line"""
    try:
        import re
        # Example: "80/tcp   open  http    nginx 1.18.0"
        match = re.search(r'(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)?', log_line)
        if match:
            return {
                "port": int(match.group(1)),
                "protocol": match.group(2),
                "state": match.group(3),
                "service": match.group(4) if match.group(4) else "unknown"
            }
    except:
        pass
    return None


def parse_nmap_vulnerability(log_line: str) -> Optional[Dict]:
    """Parse Nmap vulnerability information"""
    try:
        import re
        # Look for CVE references
        cve_match = re.search(r'(CVE-\d{4}-\d+)', log_line, re.IGNORECASE)
        if cve_match:
            return {
                "type": "cve",
                "cve_id": cve_match.group(1).upper(),
                "description": log_line.strip(),
                "severity": "medium"
            }
        
        # Look for vulnerability keywords
        if any(word in log_line.lower() for word in ['vulnerable', 'exploit', 'backdoor']):
            return {
                "type": "vulnerability",
                "description": log_line.strip(),
                "severity": "medium"
            }
    except:
        pass
    return None


def parse_nikto_finding(log_line: str) -> Optional[Dict]:
    """Parse Nikto finding from log line"""
    try:
        # Example: "+ OSVDB-3092: /admin/: This might be interesting..."
        if "+" in log_line:
            parts = log_line.split(":", 2)
            if len(parts) >= 2:
                return {
                    "type": "web_vulnerability",
                    "path": parts[1].strip() if len(parts) > 1 else "",
                    "description": parts[2].strip() if len(parts) > 2 else log_line,
                    "severity": "low"
                }
    except:
        pass
    return None


def parse_sqlmap_finding(log_line: str) -> Optional[Dict]:
    """Parse SQLMap injection finding"""
    try:
        if "parameter" in log_line.lower() and "vulnerable" in log_line.lower():
            return {
                "type": "sql_injection",
                "description": log_line.strip(),
                "severity": "high"
            }
    except:
        pass
    return None


def calculate_risk_level(vulnerabilities: List, findings: List) -> str:
    """Calculate overall risk level based on findings"""
    total = len(vulnerabilities) + len(findings)
    
    high_severity = sum(1 for v in vulnerabilities if v.get('severity') == 'high')
    
    if high_severity > 0 or total > 15:
        return "critical"
    elif total > 10:
        return "high"
    elif total > 5:
        return "medium"
    else:
        return "low"


@router.websocket("/ws/scan/{scan_id}")
async def websocket_scan_endpoint(websocket: WebSocket, scan_id: str):
    """
    WebSocket endpoint for real-time scan updates
    
    Usage:
        ws://localhost:8000/api/realtime/ws/scan/{scan_id}
    """
    await scan_manager.connect(scan_id, websocket)
    
    try:
        while True:
            # Keep connection alive
            data = await websocket.receive_text()
            
            # Handle client commands
            if data == "ping":
                await websocket.send_json({"type": "pong"})
            elif data == "cancel":
                await websocket.send_json({"type": "cancelled"})
                break
                
    except WebSocketDisconnect:
        scan_manager.disconnect(scan_id)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        scan_manager.disconnect(scan_id)


@router.post("/scan/nmap/realtime")
async def nmap_realtime_scan(
    target: str,
    scan_type: str = "quick",
    user_data: dict = Depends(verify_token)
):
    """
    Start real-time Nmap scan with WebSocket streaming
    
    Args:
        target: IP address or hostname
        scan_type: quick, full, vuln, etc.
    
    Returns:
        scan_id and websocket URL for real-time updates
    """
    if not DOCKER_AVAILABLE:
        raise HTTPException(status_code=503, detail="Docker not available")
    
    try:
        # Create scan record
        scan = create_scan(
            user_id=user_data['user_id'],
            target=target,
            scan_type='nmap',
            tool='nmap-docker'
        )
        scan_id = str(scan['id'])
        
        # Send initial connection message
        await scan_manager.send_update(scan_id, {
            "type": "initialized",
            "message": "Scan initialized, starting Docker container...",
            "timestamp": datetime.now().isoformat()
        })
        
        # Build Docker command
        nmap_args = build_nmap_args(target, scan_type)
        
        # Start Docker container
        container = docker_client.containers.run(
            "instrumentisto/nmap",
            command=nmap_args,
            detach=True,
            remove=False,
            network_mode="bridge",
            mem_limit="512m",
            cpu_quota=50000
        )
        
        logger.info(f"Started Docker container {container.id} for scan {scan_id}")
        
        # Stream logs asynchronously (don't wait)
        asyncio.create_task(stream_docker_logs(container, scan_id, "nmap"))
        
        return {
            "success": True,
            "scan_id": scan_id,
            "websocket_url": f"ws://localhost:8000/api/realtime/ws/scan/{scan_id}",
            "message": "Scan started. Connect to WebSocket for real-time updates.",
            "container_id": container.id[:12]
        }
        
    except Exception as e:
        logger.error(f"Failed to start realtime scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan/nikto/realtime")
async def nikto_realtime_scan(
    url: str,
    user_data: dict = Depends(verify_token)
):
    """
    Start real-time Nikto web scan with WebSocket streaming
    """
    if not DOCKER_AVAILABLE:
        raise HTTPException(status_code=503, detail="Docker not available")
    
    try:
        # Create scan record
        scan = create_scan(
            user_id=user_data['user_id'],
            target=url,
            scan_type='nikto',
            tool='nikto-docker'
        )
        scan_id = str(scan['id'])
        
        # Start Docker container
        container = docker_client.containers.run(
            "frapsoft/nikto",
            command=f"-h {url} -Tuning 1234567890abcde",
            detach=True,
            remove=False,
            network_mode="bridge",
            mem_limit="1g"
        )
        
        # Stream logs asynchronously
        asyncio.create_task(stream_docker_logs(container, scan_id, "nikto"))
        
        return {
            "success": True,
            "scan_id": scan_id,
            "websocket_url": f"ws://localhost:8000/api/realtime/ws/scan/{scan_id}",
            "message": "Nikto scan started. Connect to WebSocket for real-time updates."
        }
        
    except Exception as e:
        logger.error(f"Failed to start Nikto scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def build_nmap_args(target: str, scan_type: str) -> List[str]:
    """Build Nmap command arguments based on scan type"""
    base_args = ["-v", "-oN", "-"]
    
    if scan_type == "quick":
        return base_args + ["-T4", "-F", target]
    elif scan_type == "full":
        return base_args + ["-p-", "-T4", target]
    elif scan_type == "vuln":
        return base_args + ["--script", "vuln", "-sV", target]
    elif scan_type == "web":
        return base_args + ["-p", "80,443,8080,8443", "--script", "http-*", target]
    elif scan_type == "stealth":
        return base_args + ["-sS", "-T2", target]
    else:
        return base_args + ["-T4", "-F", target]
