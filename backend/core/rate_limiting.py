"""
Rate Limiting Middleware
Protects API endpoints from abuse
"""

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request, Response
import os

# Initialize limiter with Redis backend
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=os.getenv("REDIS_URL", "redis://localhost:6380/1"),
    default_limits=["100/minute"],  # Global default
    headers_enabled=True,  # Add rate limit headers to responses
)

# Custom rate limit handler
def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> Response:
    """Custom handler for rate limit exceeded"""
    return Response(
        content=f"Rate limit exceeded: {exc.detail}",
        status_code=429,
        headers={
            "X-RateLimit-Limit": str(exc.limit),
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": str(exc.reset),
            "Retry-After": str(exc.reset - int(exc.reset))
        }
    )

# Rate limit decorators for different tiers
def free_tier_limit():
    """Rate limit for free tier users: 5 scans/hour"""
    return limiter.limit("5/hour")

def pro_tier_limit():
    """Rate limit for pro tier users: 100 scans/hour"""
    return limiter.limit("100/hour")

def api_read_limit():
    """Rate limit for read operations: 100/minute"""
    return limiter.limit("100/minute")

def api_write_limit():
    """Rate limit for write operations: 20/minute"""
    return limiter.limit("20/minute")

def scan_limit():
    """Rate limit for scan endpoints: 10/minute"""
    return limiter.limit("10/minute")

def cve_search_limit():
    """Rate limit for CVE searches: 30/minute"""
    return limiter.limit("30/minute")

def ai_chat_limit():
    """Rate limit for AI chat: 20/minute"""
    return limiter.limit("20/minute")
