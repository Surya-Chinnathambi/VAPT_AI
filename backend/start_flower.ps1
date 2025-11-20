# Start Flower (Celery Monitoring Dashboard)
# Access at http://localhost:5555

cd D:\CyberShieldAI\CyberShieldAI\backend

Write-Host "`n🌸 Starting Flower Monitoring Dashboard...`n" -ForegroundColor Magenta
Write-Host "Access at: http://localhost:5555`n" -ForegroundColor Green

celery -A workers.celery_app flower --port=5555
