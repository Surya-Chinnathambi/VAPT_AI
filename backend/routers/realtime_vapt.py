"""
Real-Time VAPT WebSocket API
Supports all 88+ security tools with live streaming
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List, Dict
import asyncio
import json
import logging
from datetime import datetime

from core.realtime_tool_executor import get_realtime_executor
from core.ai_security_prompts import TOOL_CONFIGS, get_system_prompt
from routers.auth import verify_token

router = APIRouter()
logger = logging.getLogger(__name__)


class RealtimeScanRequest(BaseModel):
    """Real-time scan request with tool selection"""
    target: str
    tools: List[str]  # List of tool names from 88+ available
    scan_type: Optional[str] = "standard"  # quick/standard/full/aggressive
    parallel: Optional[bool] = True
    max_parallel: Optional[int] = 5


class ConnectionManager:
    """
    Manages WebSocket connections for real-time VAPT scans
    Supports multiple concurrent scans with independent streams
    """
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.scan_metadata: Dict[str, Dict] = {}
    
    async def connect(self, scan_id: str, websocket: WebSocket):
        """Register new WebSocket connection"""
        await websocket.accept()
        self.active_connections[scan_id] = websocket
        self.scan_metadata[scan_id] = {
            "connected_at": datetime.now().isoformat(),
            "messages_sent": 0,
            "status": "connected"
        }
        logger.info(f"✅ WebSocket connected: {scan_id}")
    
    def disconnect(self, scan_id: str):
        """Remove WebSocket connection"""
        if scan_id in self.active_connections:
            del self.active_connections[scan_id]
        if scan_id in self.scan_metadata:
            del self.scan_metadata[scan_id]
        logger.info(f"❌ WebSocket disconnected: {scan_id}")
    
    async def send_message(self, scan_id: str, message: dict):
        """
        Send real-time message to client
        
        Message types:
        - tool_start: Tool execution started
        - log: Individual log line
        - vulnerability_found: Real-time vulnerability detected
        - progress: Progress percentage update
        - tool_complete: Tool finished
        - parallel_start: Parallel execution started
        - parallel_complete: All parallel tools finished
        - error: Error occurred
        - heartbeat: Keep-alive ping
        """
        if scan_id in self.active_connections:
            try:
                await self.active_connections[scan_id].send_json(message)
                self.scan_metadata[scan_id]["messages_sent"] += 1
            except Exception as e:
                logger.error(f"Failed to send message to {scan_id}: {e}")
                self.disconnect(scan_id)
    
    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients"""
        for scan_id in list(self.active_connections.keys()):
            await self.send_message(scan_id, message)
    
    def get_stats(self) -> Dict:
        """Get connection statistics"""
        return {
            "active_connections": len(self.active_connections),
            "scans": list(self.scan_metadata.keys()),
            "total_messages": sum(meta.get("messages_sent", 0) for meta in self.scan_metadata.values())
        }


connection_manager = ConnectionManager()


@router.post("/realtime/scan")
async def start_realtime_scan(
    request: RealtimeScanRequest,
    background_tasks: BackgroundTasks,
    user_data: dict = Depends(verify_token)
):
    """
    Start real-time VAPT scan with live WebSocket updates
    
    **Supports 88+ Security Tools:**
    - Network: nmap, masscan, zmap
    - Web: nuclei, nikto, wpscan, sqlmap, xsstrike
    - SSL/TLS: testssl.sh, sslyze, sslscan
    - DNS: sublist3r, amass, dnsenum, fierce
    - API: arjun, kiterunner
    - Cloud: scoutsuite, prowler
    - Container: trivy, grype
    - ... and 70+ more!
    
    **Example:**
    ```json
    {
        "target": "https://testphp.vulnweb.com",
        "tools": ["nmap", "nuclei", "nikto", "testssl"],
        "scan_type": "standard",
        "parallel": true,
        "max_parallel": 5
    }
    ```
    
    **Returns:**
    ```json
    {
        "scan_id": "scan_123456",
        "websocket_url": "ws://localhost:8000/api/realtime/stream/scan_123456",
        "tools_queued": 4,
        "estimated_duration": "5-30 minutes"
    }
    ```
    """
    # Validate tools
    invalid_tools = [t for t in request.tools if t not in TOOL_CONFIGS]
    if invalid_tools:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid tools: {invalid_tools}. Use /realtime/tools to see available tools."
        )
    
    # Generate scan ID
    scan_id = f"scan_{datetime.now().timestamp()}"
    
    # Estimate duration
    tool_durations = {
        "nmap": 2, "nuclei": 5, "nikto": 3, "testssl": 2,
        "sqlmap": 10, "wpscan": 4, "trivy": 1, "sublist3r": 3
    }
    
    if request.parallel:
        # Parallel: max tool duration
        estimated_minutes = max(tool_durations.get(t, 3) for t in request.tools)
    else:
        # Sequential: sum of all durations
        estimated_minutes = sum(tool_durations.get(t, 3) for t in request.tools)
    
    # Queue background scan
    background_tasks.add_task(
        execute_realtime_scan,
        scan_id,
        request.target,
        request.tools,
        request.scan_type,
        request.parallel,
        request.max_parallel
    )
    
    return {
        "success": True,
        "scan_id": scan_id,
        "websocket_url": f"ws://localhost:8000/api/realtime/stream/{scan_id}",
        "tools_queued": len(request.tools),
        "parallel_execution": request.parallel,
        "estimated_duration": f"{estimated_minutes}-{estimated_minutes*2} minutes",
        "message": "Connect to WebSocket URL for real-time updates"
    }


@router.websocket("/realtime/stream/{scan_id}")
async def realtime_stream(websocket: WebSocket, scan_id: str):
    """
    WebSocket endpoint for real-time scan updates
    
    **Message Types Received:**
    
    1. **tool_start** - Tool execution started
    ```json
    {
        "type": "tool_start",
        "tool": "nmap",
        "target": "example.com",
        "scan_type": "standard",
        "timestamp": "2025-11-20T10:30:00"
    }
    ```
    
    2. **log** - Individual log line
    ```json
    {
        "type": "log",
        "tool": "nmap",
        "line": "Discovered open port 443/tcp",
        "line_number": 42,
        "timestamp": "2025-11-20T10:30:05"
    }
    ```
    
    3. **vulnerability_found** - Real-time vulnerability detected
    ```json
    {
        "type": "vulnerability_found",
        "tool": "nuclei",
        "vulnerability": {
            "type": "sql_injection",
            "severity": "critical",
            "details": "..."
        },
        "findings_count": 5,
        "timestamp": "2025-11-20T10:30:10"
    }
    ```
    
    4. **progress** - Progress update
    ```json
    {
        "type": "progress",
        "tool": "nmap",
        "percentage": 45,
        "lines_processed": 2250,
        "timestamp": "2025-11-20T10:30:15"
    }
    ```
    
    5. **tool_complete** - Tool finished
    ```json
    {
        "type": "tool_complete",
        "tool": "nmap",
        "duration": 120.5,
        "findings_count": 8,
        "success": true,
        "timestamp": "2025-11-20T10:32:00"
    }
    ```
    
    6. **parallel_complete** - All tools finished
    ```json
    {
        "type": "parallel_complete",
        "tools_count": 4,
        "success_count": 4,
        "results_summary": [...],
        "timestamp": "2025-11-20T10:35:00"
    }
    ```
    """
    await connection_manager.connect(scan_id, websocket)
    
    try:
        # Keep connection alive
        while True:
            # Wait for client message or timeout
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                
                # Handle client commands
                try:
                    command = json.loads(data)
                    if command.get("action") == "ping":
                        await websocket.send_json({"type": "pong", "timestamp": datetime.now().isoformat()})
                    elif command.get("action") == "status":
                        stats = connection_manager.get_stats()
                        await websocket.send_json({"type": "status", "data": stats})
                except json.JSONDecodeError:
                    pass
            
            except asyncio.TimeoutError:
                # Send heartbeat
                await websocket.send_json({
                    "type": "heartbeat",
                    "timestamp": datetime.now().isoformat()
                })
    
    except WebSocketDisconnect:
        connection_manager.disconnect(scan_id)
        logger.info(f"Client disconnected: {scan_id}")
    
    except Exception as e:
        logger.error(f"WebSocket error for {scan_id}: {e}")
        connection_manager.disconnect(scan_id)


@router.get("/realtime/tools")
async def get_available_tools():
    """
    Get list of all 88+ available security tools
    
    **Returns:**
    ```json
    {
        "total_tools": 88,
        "categories": {
            "network": ["nmap", "masscan", "zmap", ...],
            "web": ["nuclei", "nikto", "wpscan", ...],
            "ssl": ["testssl.sh", "sslyze", ...],
            "dns": ["sublist3r", "amass", ...],
            ...
        },
        "tools": {
            "nmap": {
                "docker_image": "instrumentisto/nmap:latest",
                "scan_types": ["quick", "standard", "stealth", "aggressive"],
                "timeout": 1800,
                "description": "Network port scanner"
            },
            ...
        }
    }
    ```
    """
    # Categorize tools
    categories = {
        "network": ["nmap", "masscan", "zmap", "rustscan"],
        "web": ["nuclei", "nikto", "wpscan", "sqlmap", "xsstrike", "zaproxy", "burpsuite"],
        "ssl": ["testssl.sh", "sslyze", "sslscan"],
        "dns": ["sublist3r", "amass", "dnsenum", "fierce", "altdns", "massdns"],
        "api": ["arjun", "kiterunner", "postman-runner"],
        "cloud": ["scoutsuite", "prowler", "cloudsploit"],
        "container": ["trivy", "grype", "anchore", "clair"],
        "code": ["semgrep", "bandit", "brakeman", "sonarqube"],
        "mobile": ["mobsf", "apktool", "jadx"],
        "exploitation": ["metasploit", "searchsploit", "exploit-db"],
        "fuzzing": ["ffuf", "gobuster", "wfuzz", "dirsearch"],
        "password": ["hydra", "medusa", "ncrack", "john"],
        "wireless": ["aircrack-ng", "wifite", "kismet"],
        "forensics": ["volatility", "autopsy", "sleuthkit"]
    }
    
    return {
        "total_tools": len(TOOL_CONFIGS),
        "categories": categories,
        "tools": TOOL_CONFIGS,
        "realtime_supported": True,
        "parallel_execution": True,
        "max_parallel_recommended": 10
    }


@router.get("/realtime/stats")
async def get_realtime_stats():
    """
    Get real-time connection statistics
    
    **Returns:**
    ```json
    {
        "active_connections": 3,
        "scans": ["scan_123", "scan_456"],
        "total_messages": 15420,
        "server_status": "healthy"
    }
    ```
    """
    stats = connection_manager.get_stats()
    executor = get_realtime_executor()
    
    return {
        **stats,
        "server_status": "healthy",
        "docker_available": executor.docker_available,
        "active_executions": len(executor.active_executions)
    }


async def execute_realtime_scan(
    scan_id: str,
    target: str,
    tools: List[str],
    scan_type: str,
    parallel: bool,
    max_parallel: int
):
    """
    Execute scan with real-time WebSocket updates
    Background task that runs tools and streams results
    """
    executor = get_realtime_executor()
    
    # Progress callback
    async def progress_callback(message: dict):
        """Forward progress to WebSocket"""
        await connection_manager.send_message(scan_id, message)
    
    try:
        # Send scan start notification
        await progress_callback({
            "type": "scan_start",
            "scan_id": scan_id,
            "target": target,
            "tools": tools,
            "scan_type": scan_type,
            "parallel": parallel,
            "timestamp": datetime.now().isoformat()
        })
        
        if parallel:
            # Parallel execution
            tasks = [
                {
                    "tool_name": tool,
                    "target": target,
                    "scan_type": scan_type
                }
                for tool in tools
            ]
            
            # Split into batches if needed
            if len(tools) > max_parallel:
                results = []
                for i in range(0, len(tasks), max_parallel):
                    batch = tasks[i:i+max_parallel]
                    batch_results = await executor.execute_parallel_realtime(batch, progress_callback)
                    results.extend(batch_results)
            else:
                results = await executor.execute_parallel_realtime(tasks, progress_callback)
        
        else:
            # Sequential execution
            results = []
            for tool in tools:
                result = await executor.execute_tool_realtime(
                    tool,
                    target,
                    scan_type,
                    progress_callback=progress_callback
                )
                results.append(result)
        
        # Send final summary
        success_count = sum(1 for r in results if r.get('success'))
        total_findings = sum(r.get('findings_count', 0) for r in results)
        
        await progress_callback({
            "type": "scan_complete",
            "scan_id": scan_id,
            "tools_run": len(tools),
            "tools_successful": success_count,
            "total_findings": total_findings,
            "results": results,
            "timestamp": datetime.now().isoformat()
        })
    
    except Exception as e:
        logger.error(f"Scan execution error ({scan_id}): {e}")
        await progress_callback({
            "type": "scan_error",
            "scan_id": scan_id,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        })


@router.post("/realtime/quick-scan")
async def quick_scan(
    target: str,
    background_tasks: BackgroundTasks,
    user_data: dict = Depends(verify_token)
):
    """
    Start quick scan with recommended tools (nmap, nuclei, nikto, testssl)
    
    **Example:**
    ```
    POST /realtime/quick-scan?target=https://example.com
    ```
    """
    recommended_tools = ["nmap", "nuclei", "nikto", "testssl"]
    
    scan_id = f"quick_{datetime.now().timestamp()}"
    
    background_tasks.add_task(
        execute_realtime_scan,
        scan_id,
        target,
        recommended_tools,
        "quick",
        True,  # parallel
        4  # max parallel
    )
    
    return {
        "success": True,
        "scan_id": scan_id,
        "websocket_url": f"ws://localhost:8000/api/realtime/stream/{scan_id}",
        "tools": recommended_tools,
        "estimated_duration": "3-5 minutes"
    }


@router.post("/realtime/full-scan")
async def full_scan(
    target: str,
    background_tasks: BackgroundTasks,
    user_data: dict = Depends(verify_token)
):
    """
    Start comprehensive scan with all relevant tools
    
    **Example:**
    ```
    POST /realtime/full-scan?target=https://example.com
    ```
    """
    comprehensive_tools = [
        "nmap", "nuclei", "nikto", "testssl", "sqlmap",
        "wpscan", "sublist3r", "amass", "ffuf", "zaproxy"
    ]
    
    scan_id = f"full_{datetime.now().timestamp()}"
    
    background_tasks.add_task(
        execute_realtime_scan,
        scan_id,
        target,
        comprehensive_tools,
        "full",
        True,  # parallel
        5  # max parallel
    )
    
    return {
        "success": True,
        "scan_id": scan_id,
        "websocket_url": f"ws://localhost:8000/api/realtime/stream/{scan_id}",
        "tools": comprehensive_tools,
        "estimated_duration": "15-30 minutes"
    }
