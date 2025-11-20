# Start Celery Worker
# Run this script to start processing background tasks

cd D:\CyberShieldAI\CyberShieldAI\backend

Write-Host "`n🚀 Starting Celery Worker...`n" -ForegroundColor Cyan

celery -A workers.celery_app worker `
    --loglevel=info `
    --pool=solo `
    --concurrency=4 `
    --queues=scans,reports,cve_updates `
    --max-tasks-per-child=100

# On Linux/Mac use:
# celery -A workers.celery_app worker --loglevel=info --concurrency=4
