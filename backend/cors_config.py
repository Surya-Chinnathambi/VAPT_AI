"""
Production-ready CORS Configuration
Update main.py to use environment-based CORS settings
"""
import os
from fastapi.middleware.cors import CORSMiddleware

def configure_cors(app):
    """
    Configure CORS based on environment
    """
    environment = os.getenv("ENVIRONMENT", "development")
    
    if environment == "production":
        # Production: Strict CORS with specific domains
        allowed_origins_str = os.getenv("ALLOWED_ORIGINS", "")
        allowed_origins = [origin.strip() for origin in allowed_origins_str.split(",") if origin.strip()]
        
        if not allowed_origins:
            # Fallback if ALLOWED_ORIGINS not set
            allowed_origins = [
                "https://cybershieldai.com",
                "https://app.cybershieldai.com",
                "https://www.cybershieldai.com"
            ]
        
        app.add_middleware(
            CORSMiddleware,
            allow_origins=allowed_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
            expose_headers=["X-Process-Time"],
            max_age=3600  # Cache preflight requests for 1 hour
        )
        
        print(f"🔒 Production CORS enabled for: {', '.join(allowed_origins)}")
    
    else:
        # Development: Allow all origins
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
            expose_headers=["*"]
        )
        
        print("⚠️  Development CORS enabled (all origins allowed)")

# Usage in main.py:
# from cors_config import configure_cors
# configure_cors(app)
