# CyberSec AI Platform - Setup Script
# This script helps you set up the project quickly

Write-Host "==================================" -ForegroundColor Cyan
Write-Host "CyberSec AI Platform - Setup" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""

# Check Docker
Write-Host "[1/6] Checking Docker..." -ForegroundColor Yellow
if (Get-Command docker -ErrorAction SilentlyContinue) {
    Write-Host "✓ Docker is installed" -ForegroundColor Green
} else {
    Write-Host "✗ Docker is not installed. Please install Docker Desktop." -ForegroundColor Red
    exit 1
}

# Check Docker Compose
Write-Host "[2/6] Checking Docker Compose..." -ForegroundColor Yellow
if (Get-Command docker-compose -ErrorAction SilentlyContinue) {
    Write-Host "✓ Docker Compose is installed" -ForegroundColor Green
} else {
    Write-Host "✗ Docker Compose is not installed." -ForegroundColor Red
    exit 1
}

# Setup environment files
Write-Host "[3/6] Setting up environment files..." -ForegroundColor Yellow
if (-not (Test-Path "backend\.env")) {
    Copy-Item "backend\.env.example" "backend\.env"
    Write-Host "✓ Created backend/.env from template" -ForegroundColor Green
    Write-Host "⚠ Please edit backend/.env with your API keys" -ForegroundColor Yellow
} else {
    Write-Host "✓ backend/.env already exists" -ForegroundColor Green
}

if (-not (Test-Path "frontend\.env")) {
    Copy-Item "frontend\.env.example" "frontend\.env"
    Write-Host "✓ Created frontend/.env from template" -ForegroundColor Green
} else {
    Write-Host "✓ frontend/.env already exists" -ForegroundColor Green
}

# Create necessary directories
Write-Host "[4/6] Creating necessary directories..." -ForegroundColor Yellow
$dirs = @("backend/chroma_db", "backend/uploads", "backend/reports")
foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "✓ Created $dir" -ForegroundColor Green
    }
}

# Ask if user wants to use Docker
Write-Host "[5/6] Setup Options" -ForegroundColor Yellow
Write-Host "1) Docker Compose (Recommended - Everything in containers)"
Write-Host "2) Manual Setup (Requires PostgreSQL, Redis installed locally)"
$choice = Read-Host "Choose setup method (1 or 2)"

if ($choice -eq "1") {
    Write-Host "[6/6] Starting services with Docker Compose..." -ForegroundColor Yellow
    docker-compose up -d
    
    Write-Host ""
    Write-Host "==================================" -ForegroundColor Cyan
    Write-Host "Setup Complete! 🎉" -ForegroundColor Green
    Write-Host "==================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Services are starting up. Please wait a moment..." -ForegroundColor Yellow
    Start-Sleep -Seconds 10
    Write-Host ""
    Write-Host "Access your application:" -ForegroundColor Green
    Write-Host "  Frontend:  http://localhost:5173" -ForegroundColor Cyan
    Write-Host "  Backend:   http://localhost:8000" -ForegroundColor Cyan
    Write-Host "  API Docs:  http://localhost:8000/docs" -ForegroundColor Cyan
    Write-Host "  Flower:    http://localhost:5555" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "View logs: docker-compose logs -f" -ForegroundColor Yellow
    Write-Host "Stop services: docker-compose down" -ForegroundColor Yellow
    
} elseif ($choice -eq "2") {
    Write-Host "[6/6] Manual setup selected" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Please ensure you have:" -ForegroundColor Yellow
    Write-Host "  - PostgreSQL running on port 5432"
    Write-Host "  - Redis running on port 6379"
    Write-Host ""
    Write-Host "Backend Setup:" -ForegroundColor Cyan
    Write-Host "  cd backend"
    Write-Host "  python -m venv venv"
    Write-Host "  .\venv\Scripts\activate"
    Write-Host "  pip install -r requirements.txt"
    Write-Host "  uvicorn main:app --reload"
    Write-Host ""
    Write-Host "Frontend Setup:" -ForegroundColor Cyan
    Write-Host "  cd frontend"
    Write-Host "  npm install"
    Write-Host "  npm run dev"
    Write-Host ""
    Write-Host "Celery Worker:" -ForegroundColor Cyan
    Write-Host "  cd backend"
    Write-Host "  celery -A celery_config worker --loglevel=info"
} else {
    Write-Host "Invalid choice. Exiting." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "1. Edit backend/.env with your API keys (Azure OpenAI, Shodan, NVD, Stripe)"
Write-Host "2. Run database migrations if needed"
Write-Host "3. Access the application and create an account"
Write-Host ""
Write-Host "For more information, see README_PROJECT.md" -ForegroundColor Yellow
