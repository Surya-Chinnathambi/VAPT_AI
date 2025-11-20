"""
Celery Worker Configuration for Background Tasks
"""
from celery import Celery
from config import CELERY_BROKER_URL, CELERY_RESULT_BACKEND

celery_app = Celery(
    'cybersec_tasks',
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND,
    include=['tasks.scan_tasks', 'tasks.report_tasks', 'tasks.cve_sync_tasks']
)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=1800,  # 30 minutes
    task_soft_time_limit=1500,  # 25 minutes
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=100,
)

# Task routing
celery_app.conf.task_routes = {
    'tasks.scan_tasks.*': {'queue': 'scans'},
    'tasks.report_tasks.*': {'queue': 'reports'},
    'tasks.cve_sync_tasks.*': {'queue': 'maintenance'},
}

if __name__ == '__main__':
    celery_app.start()
