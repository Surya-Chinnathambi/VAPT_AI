import asyncio
import sys
import os

# Add backend directory to python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from mcp_server.server import MCPServer

if __name__ == "__main__":
    server = MCPServer()
    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:
        pass
