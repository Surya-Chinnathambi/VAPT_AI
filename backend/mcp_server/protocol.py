from typing import Any, Dict, List, Optional, Union, Literal
from pydantic import BaseModel, Field

# JSON-RPC 2.0 Types
class JsonRpcRequest(BaseModel):
    jsonrpc: Literal["2.0"] = "2.0"
    method: str
    params: Optional[Dict[str, Any]] = None
    id: Optional[Union[str, int]] = None

class JsonRpcResponse(BaseModel):
    jsonrpc: Literal["2.0"] = "2.0"
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None
    id: Optional[Union[str, int]] = None

class JsonRpcNotification(BaseModel):
    jsonrpc: Literal["2.0"] = "2.0"
    method: str
    params: Optional[Dict[str, Any]] = None

# MCP Specific Types
class Tool(BaseModel):
    name: str
    description: Optional[str] = None
    inputSchema: Dict[str, Any]

class CallToolRequest(BaseModel):
    name: str
    arguments: Optional[Dict[str, Any]] = None

class CallToolResult(BaseModel):
    content: List[Dict[str, Any]]
    isError: Optional[bool] = False

class Resource(BaseModel):
    uri: str
    name: str
    description: Optional[str] = None
    mimeType: Optional[str] = None

class ReadResourceResult(BaseModel):
    contents: List[Dict[str, Any]]

class Prompt(BaseModel):
    name: str
    description: Optional[str] = None
    arguments: Optional[List[Dict[str, Any]]] = None

class GetPromptResult(BaseModel):
    description: Optional[str] = None
    messages: List[Dict[str, Any]]
