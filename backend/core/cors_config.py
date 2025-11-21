"""
CORS Configuration
Secure Cross-Origin Resource Sharing settings
"""

import os
from fastapi.middleware.cors import CORSMiddleware
from typing import List


def get_allowed_origins() -> List[str]:
    """
    Get allowed CORS origins from environment variable
    
    In production, this should be a specific list of domains
    In development, we allow localhost
    """
    env_origins = os.getenv("ALLOWED_ORIGINS", "")
    
    if env_origins:
        # Parse comma-separated origins from environment
        origins = [origin.strip() for origin in env_origins.split(",")]
    else:
        # Default development origins
        origins = [
            "http://localhost:3000",  # React dev server
            "http://localhost:5173",  # Vite dev server
            "http://localhost:5174",  # Vite dev server (alternate port)
            "http://localhost:8000",  # FastAPI docs
            "http://127.0.0.1:3000",
            "http://127.0.0.1:5173",
            "http://127.0.0.1:5174",
            "http://127.0.0.1:8000",
        ]
    
    # Never allow wildcard in production
    if os.getenv("ENVIRONMENT") == "production":
        origins = [o for o in origins if o != "*"]
    
    return origins


def configure_cors(app):
    """
    Configure CORS middleware with secure settings
    
    Args:
        app: FastAPI application instance
    """
    allowed_origins = get_allowed_origins()
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,  # Specific origins only
        allow_credentials=True,  # Allow cookies
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-Requested-With",
            "X-CSRF-Token",
        ],
        expose_headers=[
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
        ],
        max_age=600,  # Cache preflight requests for 10 minutes
    )
    
    return allowed_origins


# CORS configuration for different environments
CORS_CONFIGS = {
    "development": {
        "allow_origins": [
            "http://localhost:3000",
            "http://localhost:5173",
            "http://localhost:5174",
            "http://localhost:8000",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:5173",
            "http://127.0.0.1:5174",
            "http://127.0.0.1:8000",
        ],
        "allow_credentials": True,
    },
    "staging": {
        "allow_origins": [
            "https://staging.yourdomain.com",
            "https://staging-api.yourdomain.com",
        ],
        "allow_credentials": True,
    },
    "production": {
        "allow_origins": [
            "https://yourdomain.com",
            "https://www.yourdomain.com",
            "https://app.yourdomain.com",
        ],
        "allow_credentials": True,
    },
}


def get_cors_config(environment: str = None):
    """
    Get CORS configuration for specific environment
    """
    if environment is None:
        environment = os.getenv("ENVIRONMENT", "development")
    
    return CORS_CONFIGS.get(environment, CORS_CONFIGS["development"])
