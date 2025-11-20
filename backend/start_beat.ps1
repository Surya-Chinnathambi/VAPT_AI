# Start Celery Beat (Scheduler)
# Run this to enable periodic tasks (CVE sync, cleanup, etc.)

cd D:\CyberShieldAI\CyberShieldAI\backend

Write-Host "`n⏰ Starting Celery Beat Scheduler...`n" -ForegroundColor Yellow

celery -A workers.celery_app beat --loglevel=info
