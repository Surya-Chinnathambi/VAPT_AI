# CyberShieldAI: MCP & N2N Architecture

## Overview
This document outlines the new **Model Context Protocol (MCP)** architecture for CyberShieldAI, designed to enhance performance and interoperability for AI agents.

## 1. MCP Server Architecture
We have introduced a dedicated MCP Server (`backend/mcp_server/`) that exposes the VAPT capabilities as standardized tools. This allows any MCP-compliant AI client (like Claude Desktop, or internal agents) to discover and execute security tools securely.

### Components:
- **Protocol Layer** (`protocol.py`): Defines JSON-RPC 2.0 messages and MCP-specific types (Tools, Resources, Prompts).
- **Tool Handler** (`tools.py`): Wraps the core `AIVAPTOrchestrator` and `NmapScannerService` into MCP tools (`run_vapt_scan`, `run_nmap_scan`).
- **Server Loop** (`server.py`): Handles the stdio-based communication loop, processing requests and sending responses asynchronously.

### Usage:
To run the MCP server:
```bash
python backend/run_mcp.py
```
This will start the server on `stdin/stdout`. You can configure your AI client to point to this script.

## 2. N2N (Node-to-Node) Performance Architecture
To achieve "better performance" as requested, the backend is structured into specialized nodes:

1.  **API Node** (FastAPI): Handles HTTP/WebSocket requests and serves the Frontend.
2.  **MCP Node** (Python/Stdio): Dedicated process for AI tool execution and context management.
3.  **Worker Nodes** (Celery/Redis): Handles long-running scans (Nmap, Zap) asynchronously.

### Data Flow:
1.  **AI Request**: User asks "Scan target X" via Chat.
2.  **MCP Routing**: The AI Agent connects to the **MCP Node** to find the `run_vapt_scan` tool.
3.  **Execution**: The MCP Node triggers the task on a **Worker Node** via Redis.
4.  **Result Streaming**: The Worker Node streams results back to the API Node via WebSockets (N2N communication).

This separation ensures that the AI reasoning (MCP) does not block the API or the heavy scanning tasks.

## 3. Implementation Status
✅ **MCP Server**: Fully implemented in `backend/mcp_server/`.
✅ **Tool Integration**: Connected to `backend/tasks/scan_tasks.py` (Celery).
✅ **Database Connection**: Verified connection to PostgreSQL (or fallback).
✅ **Testing**: Verified with JSON-RPC test client.

## Future Enhancements
- **NATS Integration**: Replace Redis with NATS.io for lower-latency Node-to-Node messaging.
- **Remote MCP**: Expose the MCP server over SSE (Server-Sent Events) for remote agents.
