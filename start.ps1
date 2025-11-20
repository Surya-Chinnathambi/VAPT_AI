# CyberShield AI - Quick Start Script
# Run this after starting Docker Desktop

Write-Host "🚀 CyberShield AI Quick Start" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Check if Docker Desktop is running
Write-Host "Checking Docker..." -ForegroundColor Yellow
try {
    docker ps | Out-Null
    Write-Host "✓ Docker is running" -ForegroundColor Green
} catch {
    Write-Host "✗ Docker is not running!" -ForegroundColor Red
    Write-Host "Please start Docker Desktop and run this script again." -ForegroundColor Yellow
    exit 1
}

# Start Docker services
Write-Host ""
Write-Host "Starting PostgreSQL and Redis..." -ForegroundColor Yellow
docker-compose up -d

Write-Host ""
Write-Host "Waiting for services to be ready..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

# Check if backend/.env exists
if (-not (Test-Path "backend/.env")) {
    Write-Host ""
    Write-Host "Creating backend/.env file..." -ForegroundColor Yellow
    
    @"
# Database Configuration
DATABASE_URL=postgresql://cyberguard:secureguard2024@localhost:5432/cyberguard
REDIS_URL=redis://localhost:6379/0

# Azure OpenAI Configuration
AZURE_OPENAI_KEY=your_azure_openai_key_here
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
AZURE_OPENAI_DEPLOYMENT=gpt-4
AZURE_OPENAI_API_VERSION=2024-02-15-preview

# API Keys
NVD_API_KEY=your_nvd_api_key_here
SHODAN_API_KEY=your_shodan_api_key_here
STRIPE_SECRET_KEY=your_stripe_secret_key_here

# Security
JWT_SECRET_KEY=$(openssl rand -hex 32)
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Application
DEBUG=true
ENVIRONMENT=development
"@ | Out-File -FilePath "backend/.env" -Encoding utf8
    
    Write-Host "✓ Created backend/.env - PLEASE ADD YOUR API KEYS!" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "✓ backend/.env already exists" -ForegroundColor Green
}

# Install Python dependencies
Write-Host ""
Write-Host "Installing Python dependencies..." -ForegroundColor Yellow
Push-Location backend
pip install -r requirements.txt
Pop-Location

# Install frontend dependencies
Write-Host ""
Write-Host "Installing frontend dependencies..." -ForegroundColor Yellow
Push-Location frontend
npm install
Pop-Location

# Start Celery worker (background)
Write-Host ""
Write-Host "Starting Celery worker..." -ForegroundColor Yellow
Push-Location backend
Start-Process powershell -ArgumentList "-NoExit", "-Command", "celery -A celery_config worker --loglevel=info --pool=solo"
Pop-Location

# Start backend (background)
Write-Host ""
Write-Host "Starting FastAPI backend..." -ForegroundColor Yellow
Push-Location backend
Start-Process powershell -ArgumentList "-NoExit", "-Command", "uvicorn main:app --reload --port 8000"
Pop-Location

# Start frontend (background)
Write-Host ""
Write-Host "Starting React frontend..." -ForegroundColor Yellow
Push-Location frontend
Start-Process powershell -ArgumentList "-NoExit", "-Command", "npm run dev"
Pop-Location

Write-Host ""
Write-Host "================================" -ForegroundColor Cyan
Write-Host "✓ All services starting!" -ForegroundColor Green
Write-Host ""
Write-Host "Services will be available at:" -ForegroundColor Cyan
Write-Host "  Frontend:  http://localhost:5174" -ForegroundColor White
Write-Host "  Backend:   http://localhost:8000" -ForegroundColor White
Write-Host "  API Docs:  http://localhost:8000/docs" -ForegroundColor White
Write-Host "  PostgreSQL: localhost:5432" -ForegroundColor White
Write-Host "  Redis:     localhost:6379" -ForegroundColor White
Write-Host ""
Write-Host "⚠️  IMPORTANT: Edit backend/.env and add your API keys!" -ForegroundColor Yellow
Write-Host "================================" -ForegroundColor Cyan
