"""
Celery Application Configuration
Handles background task processing for scans, reports, and AI operations
"""

from celery import Celery
import os
from dotenv import load_dotenv

load_dotenv()

# Redis connection
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6380/0")

# Create Celery app
celery_app = Celery(
    "cybershield",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=[
        "workers.scan_tasks",
        "workers.report_tasks",
        "workers.cve_tasks"
    ]
)

# Celery configuration
celery_app.conf.update(
    # Task settings
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    
    # Task routing
    task_routes={
        "workers.scan_tasks.*": {"queue": "scans"},
        "workers.report_tasks.*": {"queue": "reports"},
        "workers.cve_tasks.*": {"queue": "cve_updates"},
    },
    
    # Task execution
    task_acks_late=True,  # Acknowledge task after completion
    worker_prefetch_multiplier=1,  # Get one task at a time
    task_time_limit=600,  # 10 minute hard limit
    task_soft_time_limit=540,  # 9 minute soft limit (warning)
    
    # Result backend
    result_expires=3600,  # Results expire after 1 hour
    result_backend_transport_options={
        "master_name": "mymaster",
        "visibility_timeout": 3600,
    },
    
    # Retries
    task_default_retry_delay=60,  # Retry after 60 seconds
    task_max_retries=3,
    
    # Worker settings
    worker_max_tasks_per_child=1000,  # Restart worker after 1000 tasks
    worker_disable_rate_limits=False,
    
    # Beat schedule (for periodic tasks)
    beat_schedule={
        "sync-cve-database": {
            "task": "workers.cve_tasks.sync_cve_database",
            "schedule": 86400.0,  # Daily (24 hours)
        },
        "cleanup-old-scans": {
            "task": "workers.scan_tasks.cleanup_old_scans",
            "schedule": 3600.0,  # Hourly
        },
    },
)

# Task success/failure handlers
@celery_app.task(bind=True)
def debug_task(self):
    """Debug task for testing Celery"""
    print(f"Request: {self.request!r}")
    return "Celery is working!"
