from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from slowapi.errors import RateLimitExceeded
import os
import time
import logging

logger = logging.getLogger(__name__)

from routers import (
    auth, scanning, chat, cve, shodan, exploits, billing, 
    reports, dashboard, compliance, vector_search, realtime_scan, vapt, realtime_vapt, ai_training
)
from core.rate_limiting import limiter, rate_limit_handler
from core.sentry_config import init_sentry
from core.security_middleware import setup_security_middleware
from core.cors_config import configure_cors

# Initialize Sentry error tracking
environment = os.getenv("ENVIRONMENT", "development")
init_sentry(environment=environment)

# Try to import new database, fallback to old one
USE_NEW_DB = False
try:
    from database.connection import init_database as init_database_new, check_database_health
    # Check if PostgreSQL is actually available
    try:
        if check_database_health():
            USE_NEW_DB = True
            print("✅ Using PostgreSQL database")
        else:
            from utils.database import init_database
            print("⚠️ PostgreSQL health check failed, using SQLite")
    except Exception as health_error:
        from utils.database import init_database
        print(f"⚠️ PostgreSQL connection failed, using SQLite: {health_error}")
except Exception as e:
    from utils.database import init_database
    print(f"⚠️ Using SQLite database: {str(e)}")

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    if USE_NEW_DB:
        init_database_new()
    else:
        init_database()
    yield
    # Shutdown (if needed)
    pass

app = FastAPI(
    title="CyberSec AI Platform API",
    description="Comprehensive cybersecurity assessment platform with AI-powered analysis",
    version="2.0.0",
    lifespan=lifespan
)

# Add rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_handler)

# Configure secure CORS
allowed_origins = configure_cors(app)
logger.info(f"CORS configured with origins: {allowed_origins}")

# Add security middleware (headers, validation, logging, etc.)
setup_security_middleware(app)

@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors(), "body": exc.body}
    )

@app.get("/")
async def root():
    return {
        "name": "CyberSec AI Platform API",
        "version": "2.0.0",
        "status": "online"
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": time.time()}

@app.get("/api/sentry-test")
async def test_sentry():
    """
    Test endpoint to verify Sentry error tracking
    Triggers a deliberate error to check Sentry integration
    """
    division_by_zero = 1 / 0  # Deliberate error for testing
    return {"message": "This should not be reached"}

app.include_router(auth.router, prefix="/api/auth", tags=["authentication"])
app.include_router(scanning.router, prefix="/api/scan", tags=["scanning"])
app.include_router(chat.router, prefix="/api/chat", tags=["ai-chat"])
app.include_router(cve.router, prefix="/api/cve", tags=["cve-database"])

# Real-time CVE intelligence endpoints
from routers import cve_realtime
app.include_router(cve_realtime.router, prefix="/api/cves", tags=["cve-realtime"])

app.include_router(shodan.router, prefix="/api/shodan", tags=["shodan"])
app.include_router(exploits.router, prefix="/api/exploits", tags=["exploits"])
app.include_router(billing.router, prefix="/api/billing", tags=["billing"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["dashboard"])
app.include_router(compliance.router, prefix="/api/compliance", tags=["compliance"])
app.include_router(vector_search.router, tags=["vector-search"])
app.include_router(vector_search.agents_router, tags=["ai-agents"])
app.include_router(realtime_scan.router, prefix="/api/realtime", tags=["realtime-scanning"])
app.include_router(realtime_vapt.router, prefix="/api/realtime", tags=["realtime-vapt-88-tools"])
app.include_router(vapt.router, prefix="/api", tags=["ai-powered-vapt"])
app.include_router(ai_training.router, tags=["AI Training"])

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
