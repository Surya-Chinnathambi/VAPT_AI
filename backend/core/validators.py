"""
Input Validation Utilities
Security-focused validators to prevent injection attacks and validate user input
"""

import re
import ipaddress
from typing import Optional
from urllib.parse import urlparse
from pydantic import validator, Field
from fastapi import HTTPException, status


class SecurityValidators:
    """Common security validation functions"""
    
    # Dangerous patterns to block
    SQL_INJECTION_PATTERNS = [
        r"('|(\\')|(;)|(--)|(\/\*)|(xp_))",  # SQL metacharacters
        r"(union|select|insert|update|delete|drop|create|alter|exec|execute)",  # SQL keywords
        r"(script|javascript|onerror|onload)",  # XSS attempts
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        r"[;&|`$(){}[\]<>]",  # Shell metacharacters
        r"(wget|curl|nc|netcat|bash|sh|powershell|cmd)",  # Command execution
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\.[/\\]",  # Directory traversal
        r"(etc/passwd|windows/system32)",  # System files
    ]
    
    @staticmethod
    def validate_no_sql_injection(value: str, field_name: str = "input") -> str:
        """Validate input doesn't contain SQL injection patterns"""
        if not value:
            return value
            
        value_lower = value.lower()
        for pattern in SecurityValidators.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value_lower, re.IGNORECASE):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid {field_name}: potential SQL injection detected"
                )
        return value
    
    @staticmethod
    def validate_no_command_injection(value: str, field_name: str = "input") -> str:
        """Validate input doesn't contain command injection patterns"""
        if not value:
            return value
            
        for pattern in SecurityValidators.COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid {field_name}: potential command injection detected"
                )
        return value
    
    @staticmethod
    def validate_no_path_traversal(value: str, field_name: str = "path") -> str:
        """Validate input doesn't contain path traversal patterns"""
        if not value:
            return value
            
        for pattern in SecurityValidators.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid {field_name}: potential path traversal detected"
                )
        return value
    
    @staticmethod
    def validate_ip_address(value: str) -> str:
        """Validate IP address format"""
        if not value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="IP address cannot be empty"
            )
        
        try:
            # Try parsing as IPv4 or IPv6
            ip = ipaddress.ip_address(value)
            
            # Block private/reserved IPs in production
            if ip.is_private or ip.is_reserved or ip.is_loopback:
                # Allow localhost/private IPs in development
                # In production, you might want to block these
                pass
                
            return value
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid IP address format: {value}"
            )
    
    @staticmethod
    def validate_ip_or_hostname(value: str) -> str:
        """Validate IP address or hostname"""
        if not value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Target cannot be empty"
            )
        
        # Check for command injection first
        SecurityValidators.validate_no_command_injection(value, "target")
        
        # Try IP address first
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            pass
        
        # Validate hostname/domain
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$'
        if not re.match(hostname_pattern, value):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid hostname format: {value}"
            )
        
        # Check length
        if len(value) > 253:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Hostname too long (max 253 characters)"
            )
        
        return value
    
    @staticmethod
    def validate_url(value: str, allowed_schemes: list = None) -> str:
        """Validate URL format and scheme"""
        if not value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="URL cannot be empty"
            )
        
        if allowed_schemes is None:
            allowed_schemes = ["http", "https"]
        
        try:
            parsed = urlparse(value)
            
            # Validate scheme
            if parsed.scheme not in allowed_schemes:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid URL scheme. Allowed: {', '.join(allowed_schemes)}"
                )
            
            # Validate netloc exists
            if not parsed.netloc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid URL: missing domain"
                )
            
            # Check for JavaScript/data URIs
            if parsed.scheme in ["javascript", "data", "file"]:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid URL scheme"
                )
            
            return value
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid URL format: {str(e)}"
            )
    
    @staticmethod
    def validate_port(value: int) -> int:
        """Validate port number"""
        if not isinstance(value, int):
            try:
                value = int(value)
            except (ValueError, TypeError):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Port must be a number"
                )
        
        if value < 1 or value > 65535:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Port must be between 1 and 65535"
            )
        
        return value
    
    @staticmethod
    def validate_port_range(value: str) -> str:
        """Validate port range format (e.g., '80,443' or '1-1024')"""
        if not value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Port range cannot be empty"
            )
        
        # Check for command injection
        SecurityValidators.validate_no_command_injection(value, "port range")
        
        # Validate format: comma-separated ports or ranges
        port_pattern = r'^[0-9,\-\s]+$'
        if not re.match(port_pattern, value):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid port range format"
            )
        
        # Validate individual ports/ranges
        parts = value.replace(" ", "").split(",")
        for part in parts:
            if "-" in part:
                # Range
                try:
                    start, end = part.split("-")
                    start_port = int(start)
                    end_port = int(end)
                    
                    if start_port < 1 or end_port > 65535:
                        raise ValueError("Port out of range")
                    if start_port > end_port:
                        raise ValueError("Invalid range")
                except ValueError:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Invalid port range: {part}"
                    )
            else:
                # Single port
                try:
                    port = int(part)
                    SecurityValidators.validate_port(port)
                except ValueError:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Invalid port: {part}"
                    )
        
        return value
    
    @staticmethod
    def validate_cve_id(value: str) -> str:
        """Validate CVE ID format"""
        if not value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="CVE ID cannot be empty"
            )
        
        # CVE format: CVE-YYYY-NNNNN
        cve_pattern = r'^CVE-\d{4}-\d{4,}$'
        if not re.match(cve_pattern, value, re.IGNORECASE):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid CVE ID format: {value}"
            )
        
        return value.upper()
    
    @staticmethod
    def sanitize_string(value: str, max_length: int = 1000) -> str:
        """Sanitize string input by removing dangerous characters"""
        if not value:
            return value
        
        # Trim whitespace
        value = value.strip()
        
        # Limit length
        if len(value) > max_length:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Input too long (max {max_length} characters)"
            )
        
        # Remove null bytes
        value = value.replace("\x00", "")
        
        # Remove control characters (except newline, tab, carriage return)
        value = "".join(char for char in value if ord(char) >= 32 or char in ['\n', '\t', '\r'])
        
        return value
    
    @staticmethod
    def validate_scan_type(value: str) -> str:
        """Validate scan type is allowed"""
        allowed_types = ["quick", "full", "vuln", "web", "stealth", "aggressive", "custom"]
        
        if value not in allowed_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid scan type. Allowed: {', '.join(allowed_types)}"
            )
        
        return value


def validate_ip_address_field(cls, v):
    """Pydantic validator for IP address fields"""
    return SecurityValidators.validate_ip_address(v)


def validate_url_field(cls, v):
    """Pydantic validator for URL fields"""
    return SecurityValidators.validate_url(v)


def validate_no_injection(cls, v):
    """Pydantic validator to prevent injection attacks"""
    if isinstance(v, str):
        SecurityValidators.validate_no_sql_injection(v)
        SecurityValidators.validate_no_command_injection(v)
        SecurityValidators.validate_no_path_traversal(v)
    return v
