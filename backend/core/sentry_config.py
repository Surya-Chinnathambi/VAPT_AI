"""
Sentry Error Tracking Configuration
Monitors production errors, performance, and user issues
"""
import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration
from sentry_sdk.integrations.starlette import StarletteIntegration
from sentry_sdk.integrations.redis import RedisIntegration
from sentry_sdk.integrations.celery import CeleryIntegration
import os
from typing import Optional

def init_sentry(environment: str = "production"):
    """
    Initialize Sentry error tracking
    
    Args:
        environment: Deployment environment (development/staging/production)
    """
    sentry_dsn = os.getenv("SENTRY_DSN")
    
    if not sentry_dsn or sentry_dsn.lower() in ['', 'disabled', 'none', 'false']:
        print("ℹ️  Sentry error tracking disabled (SENTRY_DSN not configured)")
        return
    
    sentry_sdk.init(
        dsn=sentry_dsn,
        # Performance Monitoring
        traces_sample_rate=0.1,  # 10% of transactions for performance monitoring
        profiles_sample_rate=0.1,  # 10% of transactions for profiling
        
        # Environment Settings
        environment=environment,
        release=os.getenv("APP_VERSION", "1.0.0"),
        
        # Integrations
        integrations=[
            FastApiIntegration(transaction_style="endpoint"),  # Track FastAPI routes
            StarletteIntegration(transaction_style="endpoint"),  # Starlette support
            RedisIntegration(),  # Track Redis operations
            CeleryIntegration(
                monitor_beat_tasks=True,  # Track Celery Beat scheduled tasks
                exclude_beat_tasks=None,  # Monitor all beat tasks
            ),
        ],
        
        # Error Filtering
        ignore_errors=[
            KeyboardInterrupt,
            SystemExit,
            # Add common non-critical errors here
        ],
        
        # PII (Personally Identifiable Information) Protection
        send_default_pii=False,  # Don't send user data automatically
        
        # Performance Settings
        max_breadcrumbs=50,  # Keep last 50 breadcrumbs for context
        attach_stacktrace=True,  # Include stack traces
        
        # Sampling
        before_send=before_send_filter,
        before_send_transaction=before_send_transaction_filter,
    )
    
    print(f"✅ Sentry initialized for {environment} environment")


def before_send_filter(event, hint):
    """
    Filter events before sending to Sentry
    Can be used to scrub sensitive data or ignore certain errors
    """
    # Don't send 404 errors
    if "exc_info" in hint:
        exc_type, exc_value, tb = hint["exc_info"]
        if isinstance(exc_value, Exception):
            if "404" in str(exc_value):
                return None
    
    # Scrub sensitive data from request headers
    if "request" in event:
        if "headers" in event["request"]:
            # Remove authorization headers
            event["request"]["headers"].pop("Authorization", None)
            event["request"]["headers"].pop("X-API-Key", None)
    
    return event


def before_send_transaction_filter(event, hint):
    """
    Filter performance transactions before sending
    Reduce noise from health checks and static assets
    """
    # Ignore health check transactions
    if event.get("transaction") in ["/health", "/api/health"]:
        return None
    
    return event


def capture_exception_with_context(
    exception: Exception,
    user_id: Optional[int] = None,
    extra_context: Optional[dict] = None
):
    """
    Manually capture an exception with additional context
    
    Args:
        exception: The exception to capture
        user_id: Optional user ID for tracking
        extra_context: Additional context data
    """
    with sentry_sdk.push_scope() as scope:
        if user_id:
            scope.set_user({"id": user_id})
        
        if extra_context:
            for key, value in extra_context.items():
                scope.set_context(key, value)
        
        sentry_sdk.capture_exception(exception)


def capture_message_with_context(
    message: str,
    level: str = "info",
    extra_context: Optional[dict] = None
):
    """
    Capture a custom message with context
    
    Args:
        message: The message to log
        level: Severity level (debug/info/warning/error/fatal)
        extra_context: Additional context data
    """
    with sentry_sdk.push_scope() as scope:
        if extra_context:
            for key, value in extra_context.items():
                scope.set_context(key, value)
        
        sentry_sdk.capture_message(message, level=level)
