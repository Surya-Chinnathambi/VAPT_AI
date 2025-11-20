# Load Testing Script for CyberShield AI
# Tests both backend and frontend with concurrent users

Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "CyberShield AI - Concurrent User Load Testing" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host ""

# Configuration
$BACKEND_DIR = "backend"
$FRONTEND_DIR = "frontend"
$BACKEND_URL = "http://localhost:8000"
$FRONTEND_URL = "http://localhost:5173"

# Function to check if service is running
function Test-ServiceRunning {
    param($Url, $ServiceName)
    
    try {
        $response = Invoke-WebRequest -Uri $Url -TimeoutSec 5 -UseBasicParsing -ErrorAction SilentlyContinue
        return $true
    } catch {
        return $false
    }
}

# Function to wait for service
function Wait-ForService {
    param($Url, $ServiceName, $MaxAttempts = 30)
    
    Write-Host "Waiting for $ServiceName to be ready..." -ForegroundColor Yellow
    
    for ($i = 1; $i -le $MaxAttempts; $i++) {
        if (Test-ServiceRunning -Url $Url -ServiceName $ServiceName) {
            Write-Host "✓ $ServiceName is ready!" -ForegroundColor Green
            return $true
        }
        Write-Host "  Attempt $i/$MaxAttempts..." -ForegroundColor Gray
        Start-Sleep -Seconds 2
    }
    
    Write-Host "✗ $ServiceName failed to start" -ForegroundColor Red
    return $false
}

# Check if backend is running
Write-Host "`n[1/5] Checking Backend Service..." -ForegroundColor Cyan
if (-not (Test-ServiceRunning -Url "$BACKEND_URL/health" -ServiceName "Backend")) {
    Write-Host "Backend is not running. Please start it first:" -ForegroundColor Yellow
    Write-Host "  cd backend" -ForegroundColor Gray
    Write-Host "  uvicorn main:app --reload" -ForegroundColor Gray
    Write-Host ""
    
    $startBackend = Read-Host "Start backend now? (y/n)"
    if ($startBackend -eq 'y') {
        Push-Location $BACKEND_DIR
        Start-Process powershell -ArgumentList "-NoExit", "-Command", "uvicorn main:app --reload"
        Pop-Location
        
        if (-not (Wait-ForService -Url "$BACKEND_URL/health" -ServiceName "Backend")) {
            exit 1
        }
    } else {
        Write-Host "Cannot run tests without backend. Exiting..." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "✓ Backend is running" -ForegroundColor Green
}

# Check if frontend is running
Write-Host "`n[2/5] Checking Frontend Service..." -ForegroundColor Cyan
if (-not (Test-ServiceRunning -Url $FRONTEND_URL -ServiceName "Frontend")) {
    Write-Host "Frontend is not running. Please start it first:" -ForegroundColor Yellow
    Write-Host "  cd frontend" -ForegroundColor Gray
    Write-Host "  npm run dev" -ForegroundColor Gray
    Write-Host ""
    
    $startFrontend = Read-Host "Start frontend now? (y/n)"
    if ($startFrontend -eq 'y') {
        Push-Location $FRONTEND_DIR
        Start-Process powershell -ArgumentList "-NoExit", "-Command", "npm run dev"
        Pop-Location
        
        if (-not (Wait-ForService -Url $FRONTEND_URL -ServiceName "Frontend")) {
            exit 1
        }
    } else {
        Write-Host "⚠ Skipping frontend tests" -ForegroundColor Yellow
    }
} else {
    Write-Host "✓ Frontend is running" -ForegroundColor Green
}

# Run backend load tests
Write-Host "`n[3/5] Running Backend Load Tests..." -ForegroundColor Cyan
Write-Host "Testing with 2-3 concurrent users..." -ForegroundColor Gray
Write-Host ""

Push-Location $BACKEND_DIR

# Install dependencies if needed
if (-not (Test-Path "venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv venv
}

# Activate virtual environment
& "venv\Scripts\Activate.ps1"

# Install test dependencies
Write-Host "Installing test dependencies..." -ForegroundColor Yellow
pip install pytest pytest-asyncio psutil httpx --quiet

# Run load tests
Write-Host ""
Write-Host "Executing backend load tests..." -ForegroundColor Cyan
pytest tests/test_load_concurrent_users.py -v -s --tb=short

$backendExitCode = $LASTEXITCODE

Pop-Location

if ($backendExitCode -eq 0) {
    Write-Host "`n✓ Backend load tests PASSED" -ForegroundColor Green
} else {
    Write-Host "`n✗ Backend load tests FAILED" -ForegroundColor Red
}

# Run frontend load tests (if frontend is running)
if (Test-ServiceRunning -Url $FRONTEND_URL -ServiceName "Frontend") {
    Write-Host "`n[4/5] Running Frontend Load Tests..." -ForegroundColor Cyan
    Write-Host "Testing with 2-3 concurrent browser sessions..." -ForegroundColor Gray
    Write-Host ""
    
    Push-Location $FRONTEND_DIR
    
    # Check if Playwright is installed
    if (-not (Test-Path "node_modules\@playwright")) {
        Write-Host "Installing Playwright..." -ForegroundColor Yellow
        npm install --save-dev @playwright/test
        npx playwright install chromium
    }
    
    # Run Playwright tests
    Write-Host ""
    Write-Host "Executing frontend load tests..." -ForegroundColor Cyan
    npx playwright test tests/load-test.spec.ts --workers=1
    
    $frontendExitCode = $LASTEXITCODE
    
    Pop-Location
    
    if ($frontendExitCode -eq 0) {
        Write-Host "`n✓ Frontend load tests PASSED" -ForegroundColor Green
    } else {
        Write-Host "`n✗ Frontend load tests FAILED" -ForegroundColor Red
    }
} else {
    Write-Host "`n[4/5] Skipping Frontend Tests (service not running)" -ForegroundColor Yellow
    $frontendExitCode = 0
}

# Summary
Write-Host "`n[5/5] Test Summary" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan

if ($backendExitCode -eq 0) {
    Write-Host "✓ Backend Load Tests: PASSED" -ForegroundColor Green
} else {
    Write-Host "✗ Backend Load Tests: FAILED" -ForegroundColor Red
}

if (Test-ServiceRunning -Url $FRONTEND_URL -ServiceName "Frontend") {
    if ($frontendExitCode -eq 0) {
        Write-Host "✓ Frontend Load Tests: PASSED" -ForegroundColor Green
    } else {
        Write-Host "✗ Frontend Load Tests: FAILED" -ForegroundColor Red
    }
} else {
    Write-Host "⚠ Frontend Load Tests: SKIPPED" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Deployment Readiness:" -ForegroundColor Cyan
if ($backendExitCode -eq 0 -and $frontendExitCode -eq 0) {
    Write-Host "  ✓ System ready for 2-3 concurrent users" -ForegroundColor Green
    Write-Host "  ✓ Performance metrics within acceptable range" -ForegroundColor Green
    Write-Host "  ✓ No critical issues detected" -ForegroundColor Green
    Write-Host ""
    Write-Host "READY FOR DEPLOYMENT! 🚀" -ForegroundColor Green
} else {
    Write-Host "  ✗ Issues detected during load testing" -ForegroundColor Red
    Write-Host "  ⚠ Review test output before deployment" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "DEPLOYMENT NOT RECOMMENDED" -ForegroundColor Red
}

Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host ""

# Exit with appropriate code
if ($backendExitCode -ne 0 -or $frontendExitCode -ne 0) {
    exit 1
}
exit 0
