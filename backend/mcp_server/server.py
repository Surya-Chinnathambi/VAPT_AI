import sys
import json
import asyncio
import logging
from typing import Optional
from mcp_server.protocol import JsonRpcRequest, JsonRpcResponse, CallToolResult
from mcp_server.tools import VaptMcpTools

# Configure logging to stderr so it doesn't interfere with stdout JSON-RPC
logging.basicConfig(stream=sys.stderr, level=logging.INFO)
logger = logging.getLogger("mcp_server")

class MCPServer:
    def __init__(self):
        self.tools_handler = VaptMcpTools()

    async def process_request(self, request: JsonRpcRequest) -> Optional[JsonRpcResponse]:
        try:
            if request.method == "tools/list":
                tools = self.tools_handler.get_tools()
                return JsonRpcResponse(
                    id=request.id,
                    result={
                        "tools": [t.dict() for t in tools]
                    }
                )
            
            elif request.method == "tools/call":
                params = request.params or {}
                name = params.get("name")
                args = params.get("arguments", {})
                
                result = await self.tools_handler.handle_call_tool(name, args)
                return JsonRpcResponse(
                    id=request.id,
                    result=result.dict()
                )
            
            elif request.method == "initialize":
                return JsonRpcResponse(
                    id=request.id,
                    result={
                        "protocolVersion": "0.1.0",
                        "capabilities": {
                            "tools": {},
                            "resources": {}
                        },
                        "serverInfo": {
                            "name": "CyberShieldAI-MCP",
                            "version": "1.0.0"
                        }
                    }
                )
            
            elif request.method == "notifications/initialized":
                # No response needed for notifications
                return None
                
            else:
                return JsonRpcResponse(
                    id=request.id,
                    error={"code": -32601, "message": "Method not found"}
                )

        except Exception as e:
            logger.error(f"Error processing request: {e}")
            return JsonRpcResponse(
                id=request.id,
                error={"code": -32000, "message": str(e)}
            )

    async def run(self):
        logger.info("Starting MCP Server...")
        
        # Read lines from stdin
        while True:
            try:
                line = await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
                if not line:
                    break
                
                try:
                    data = json.loads(line)
                    request = JsonRpcRequest(**data)
                    
                    response = await self.process_request(request)
                    
                    if response:
                        sys.stdout.write(response.json() + "\n")
                        sys.stdout.flush()
                        
                except json.JSONDecodeError:
                    logger.error("Invalid JSON received")
                except Exception as e:
                    logger.error(f"Error handling line: {e}")
                    
            except Exception as e:
                logger.error(f"Fatal error in loop: {e}")
                break

if __name__ == "__main__":
    server = MCPServer()
    asyncio.run(server.run())
