param(
    [switch]$Rebuild,
    [switch]$RunTests,
    [string]$DemoTarget = "https://juice-shop.herokuapp.com"
)

$ErrorActionPreference = "Stop"

Write-Host "[Orchestrator] Starting full VAPT stack orchestration..." -ForegroundColor Cyan

# 1) Optional cleanup
if ($Rebuild) {
    Write-Host "[Orchestrator] Rebuilding images (docker compose build)..." -ForegroundColor Yellow
    docker compose build
}

# 2) Bring up stack
Write-Host "[Orchestrator] Bringing up Docker stack (detached)..." -ForegroundColor Yellow
if (Test-Path "docker-compose.prod.yml") {
    docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
} elseif (Test-Path "docker-compose.yml") {
    docker compose up -d
} else {
    Write-Error "docker-compose.yml not found at repo root."
    exit 1
}

# 3) Wait for backend health
Write-Host "[Orchestrator] Waiting for backend health endpoint..." -ForegroundColor Yellow
$healthUrl = "http://localhost:8000/health"
$maxAttempts = 60
$attempt = 0

while ($attempt -lt $maxAttempts) {
    try {
        $resp = Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 5
        if ($resp.StatusCode -eq 200) {
            Write-Host "[Orchestrator] Backend is healthy." -ForegroundColor Green
            break
        }
    } catch {
        Start-Sleep -Seconds 5
        $attempt++
        Write-Host "[Orchestrator] Backend not ready yet (attempt $attempt)..." -ForegroundColor DarkYellow
    }
}

if ($attempt -ge $maxAttempts) {
    Write-Error "Backend did not become healthy in time."
    exit 1
}

# 4) Optional tests (backend)
if ($RunTests) {
    Write-Host "[Orchestrator] Running backend tests..." -ForegroundColor Yellow
    Push-Location "backend"
    try {
        pytest -q
    } finally {
        Pop-Location
    }
}

# 5) Optional demo scan via realtime VAPT API (non-blocking on failure)
try {
    Write-Host "[Orchestrator] Triggering demo realtime VAPT scan on $DemoTarget ..." -ForegroundColor Yellow
    $body = @{ target = $DemoTarget; intensity = "standard" } | ConvertTo-Json
    $scanResp = Invoke-WebRequest -Uri "http://localhost:8000/api/vapt/realtime/full-scan" -Method POST -ContentType "application/json" -Body $body -UseBasicParsing
    Write-Host "[Orchestrator] Demo scan response status: $($scanResp.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "[Orchestrator] Demo scan failed (this does not stop the stack)." -ForegroundColor DarkYellow
}

Write-Host "[Orchestrator] Stack is up. Frontend should be available on your configured port (e.g. http://localhost:5173)." -ForegroundColor Cyan
