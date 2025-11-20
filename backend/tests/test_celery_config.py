"""
Celery Background Tasks Tests
Tests for Celery configuration and task registration
"""
import pytest
from celery.app.task import Task


@pytest.mark.unit
def test_celery_app_configuration():
    """Test that Celery app is properly configured"""
    from workers.celery_app import celery_app
    
    assert celery_app is not None
    assert celery_app.conf.broker_url is not None
    assert "redis://" in celery_app.conf.broker_url


@pytest.mark.unit
def test_scan_task_registration():
    """Test that scan tasks are registered"""
    from workers.celery_app import celery_app
    
    task_names = [name for name in celery_app.tasks.keys() if not name.startswith("celery.")]
    
    # Should have at least some tasks registered
    assert len(task_names) > 0
    # Should include scan-related tasks
    scan_tasks = [t for t in task_names if "scan" in t.lower() or "nmap" in t.lower()]
    assert len(scan_tasks) > 0


@pytest.mark.unit
def test_cleanup_task_exists():
    """Test that cleanup task exists"""
    from workers.celery_app import celery_app
    
    task_names = list(celery_app.tasks.keys())
    # Should have cleanup task
    cleanup_tasks = [t for t in task_names if "cleanup" in t.lower()]
    assert len(cleanup_tasks) > 0


@pytest.mark.unit
def test_cve_sync_task_exists():
    """Test that CVE sync task exists"""
    from workers.celery_app import celery_app
    
    task_names = list(celery_app.tasks.keys())
    # Check beat schedule has CVE sync
    beat_schedule = celery_app.conf.beat_schedule
    assert any("cve" in task.lower() or "sync" in task.lower() 
               for task in beat_schedule.keys())


@pytest.mark.unit
def test_report_generation_task_exists():
    """Test that report generation task exists"""
    from workers.celery_app import celery_app
    
    # Check if there are any report tasks in beat schedule
    beat_schedule = celery_app.conf.beat_schedule
    # Or check task routing has report tasks
    assert celery_app.conf.task_routes is not None
    assert "workers.report_tasks.*" in celery_app.conf.task_routes


@pytest.mark.unit
def test_celery_beat_schedule():
    """Test Celery Beat schedule is configured"""
    from workers.celery_app import celery_app
    
    beat_schedule = celery_app.conf.beat_schedule
    
    assert beat_schedule is not None
    assert "sync-cve-database" in beat_schedule
    assert "cleanup-old-scans" in beat_schedule


@pytest.mark.unit
def test_task_routing():
    """Test that task routing is configured"""
    from workers.celery_app import celery_app
    
    task_routes = celery_app.conf.task_routes
    
    assert task_routes is not None
    # Should route scan tasks to 'scans' queue
    assert "workers.scan_tasks.*" in task_routes
    assert task_routes["workers.scan_tasks.*"]["queue"] == "scans"
