"""
WebSocket endpoint for real-time VAPT execution
Streams live progress, logs, and results to frontend
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query
from typing import Dict, List
import json
import asyncio
import logging

# from routers.auth import verify_token_ws  # TODO: Implement WebSocket auth
from services.realtime_vapt_workflow import get_realtime_vapt_workflow

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ws", tags=["WebSocket"])


class ConnectionManager:
    """Manages WebSocket connections"""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
    
    async def connect(self, websocket: WebSocket, client_id: str):
        """Accept and store WebSocket connection"""
        await websocket.accept()
        self.active_connections[client_id] = websocket
        logger.info(f"WebSocket client {client_id} connected")
    
    def disconnect(self, client_id: str):
        """Remove WebSocket connection"""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
            logger.info(f"WebSocket client {client_id} disconnected")
    
    async def send_message(self, client_id: str, message: dict):
        """Send message to specific client"""
        if client_id in self.active_connections:
            try:
                await self.active_connections[client_id].send_json(message)
            except Exception as e:
                logger.error(f"Error sending to {client_id}: {e}")
                self.disconnect(client_id)
    
    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients"""
        disconnected = []
        for client_id, websocket in self.active_connections.items():
            try:
                await websocket.send_json(message)
            except Exception as e:
                logger.error(f"Error broadcasting to {client_id}: {e}")
                disconnected.append(client_id)
        
        for client_id in disconnected:
            self.disconnect(client_id)


manager = ConnectionManager()


@router.websocket("/vapt")
async def vapt_websocket(
    websocket: WebSocket,
    token: str = Query(...),
    client_id: str = Query(...)
):
    """
    WebSocket endpoint for real-time VAPT execution
    
    Usage:
        ws://localhost:8000/api/ws/vapt?token=JWT_TOKEN&client_id=unique_id
    
    Messages sent to client:
        - workflow_started: VAPT workflow initiated
        - phase_started: New phase beginning
        - tool_start: Tool execution started
        - tool_progress: Tool progress update
        - tool_complete: Tool finished
        - phase_completed: Phase finished
        - workflow_completed: Full workflow done
        - error: Error occurred
    
    Messages from client:
        - start_scan: {"target": "example.com", "intensity": "standard"}
        - cancel_scan: {"scan_id": "..."}
    """
    try:
        # Verify token
        # TODO: Implement proper WebSocket token verification
        # user_data = await verify_token_ws(token)
        
        await manager.connect(websocket, client_id)
        
        await websocket.send_json({
            "type": "connected",
            "client_id": client_id,
            "message": "WebSocket connection established"
        })
        
        # Wait for scan requests
        while True:
            try:
                data = await websocket.receive_json()
                
                if data.get("action") == "start_scan":
                    # Start real-time VAPT scan
                    target = data.get("target")
                    intensity = data.get("intensity", "standard")
                    phases = data.get("phases")
                    
                    if not target:
                        await websocket.send_json({
                            "type": "error",
                            "message": "Target required"
                        })
                        continue
                    
                    # Create progress callback for this client
                    async def progress_callback(progress_data: dict):
                        await manager.send_message(client_id, progress_data)
                    
                    # Execute VAPT workflow
                    workflow = get_realtime_vapt_workflow(progress_callback=progress_callback)
                    
                    # Run in background task
                    asyncio.create_task(
                        execute_vapt_with_updates(
                            workflow,
                            target,
                            intensity,
                            phases,
                            client_id
                        )
                    )
                    
                    await websocket.send_json({
                        "type": "scan_initiated",
                        "target": target,
                        "intensity": intensity
                    })
                
                elif data.get("action") == "cancel_scan":
                    # TODO: Implement scan cancellation
                    await websocket.send_json({
                        "type": "info",
                        "message": "Scan cancellation not yet implemented"
                    })
                
                elif data.get("action") == "ping":
                    await websocket.send_json({
                        "type": "pong",
                        "timestamp": data.get("timestamp")
                    })
            
            except WebSocketDisconnect:
                logger.info(f"Client {client_id} disconnected")
                manager.disconnect(client_id)
                break
            
            except json.JSONDecodeError:
                await websocket.send_json({
                    "type": "error",
                    "message": "Invalid JSON format"
                })
            
            except Exception as e:
                logger.error(f"WebSocket error for client {client_id}: {e}")
                await websocket.send_json({
                    "type": "error",
                    "message": str(e)
                })
    
    except Exception as e:
        logger.error(f"WebSocket connection error: {e}")
        manager.disconnect(client_id)


async def execute_vapt_with_updates(
    workflow,
    target: str,
    intensity: str,
    phases: List[str],
    client_id: str
):
    """Execute VAPT workflow and send final results"""
    try:
        result = await workflow.execute_full_vapt(
            target=target,
            intensity=intensity,
            phases=phases
        )
        
        # Send final results
        await manager.send_message(client_id, {
            "type": "final_results",
            "success": result.get("success"),
            "duration": result.get("duration"),
            "findings_count": len(result.get("findings", [])),
            "results": result
        })
    
    except Exception as e:
        logger.error(f"VAPT execution error: {e}")
        await manager.send_message(client_id, {
            "type": "execution_error",
            "error": str(e)
        })


@router.websocket("/scan/{scan_type}")
async def tool_scan_websocket(
    websocket: WebSocket,
    scan_type: str,
    token: str = Query(...),
    client_id: str = Query(...)
):
    """
    WebSocket for single tool execution with real-time logs
    
    Args:
        scan_type: nmap, nuclei, nikto, etc.
    """
    try:
        await manager.connect(websocket, client_id)
        
        await websocket.send_json({
            "type": "connected",
            "scan_type": scan_type,
            "client_id": client_id
        })
        
        while True:
            try:
                data = await websocket.receive_json()
                
                if data.get("action") == "start":
                    target = data.get("target")
                    scan_options = data.get("scan_type", "standard")
                    
                    if not target:
                        await websocket.send_json({
                            "type": "error",
                            "message": "Target required"
                        })
                        continue
                    
                    # Create progress callback
                    async def tool_progress(progress_data: dict):
                        await manager.send_message(client_id, progress_data)
                    
                    # Execute tool
                    from core.realtime_tool_executor import RealtimeToolExecutor
                    executor = RealtimeToolExecutor()
                    
                    result = await executor.execute_tool_realtime(
                        tool_name=scan_type,
                        target=target,
                        scan_type=scan_options,
                        progress_callback=tool_progress
                    )
                    
                    await websocket.send_json({
                        "type": "scan_complete",
                        "result": result
                    })
            
            except WebSocketDisconnect:
                logger.info(f"Tool scan client {client_id} disconnected")
                manager.disconnect(client_id)
                break
            
            except Exception as e:
                logger.error(f"Tool scan error: {e}")
                await websocket.send_json({
                    "type": "error",
                    "message": str(e)
                })
    
    except Exception as e:
        logger.error(f"WebSocket tool scan error: {e}")
        manager.disconnect(client_id)


@router.get("/stats")
async def get_websocket_stats():
    """Get WebSocket connection statistics"""
    return {
        "active_connections": len(manager.active_connections),
        "connected_clients": list(manager.active_connections.keys())
    }
