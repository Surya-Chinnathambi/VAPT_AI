from pydantic import BaseModel, validator
from typing import Optional, List, Dict, Any
from datetime import datetime

class ScanRequest(BaseModel):
    target: str
    scan_type: str
    options: Optional[Dict[str, Any]] = {}

class PortScanRequest(BaseModel):
    host: str
    ports: Optional[List[int]] = None
    scan_type: Optional[str] = "common"
    
    @validator('host')
    def validate_host(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Host cannot be empty')
        return v.strip()

class WebScanRequest(BaseModel):
    url: str
    options: Optional[Dict[str, bool]] = {
        "scan_ssl": True,
        "scan_headers": True,
        "scan_paths": True,
        "scan_methods": True
    }
    
    @validator('url')
    def validate_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return v

class ScanResponse(BaseModel):
    id: int
    user_id: int
    scan_type: str
    target: str
    status: str
    results: Optional[Dict[str, Any]] = None
    created_at: datetime
    completed_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True
