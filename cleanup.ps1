# Cleanup Script - Remove Unwanted Files
# This script removes old Streamlit files, cache directories, and temporary files

Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "CyberShield AI - Repository Cleanup" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host ""

$removed = 0
$errors = 0

# 1. Remove old Streamlit Python files from root
Write-Host "[1/5] Removing old Streamlit files from root..." -ForegroundColor Yellow

$streamlitFiles = @(
    "ai_chat.py",
    "app.py",
    "auth.py",
    "billing.py",
    "cve_database.py",
    "dashboard.py",
    "database.py",
    "exploit_database.py",
    "port_scanner.py",
    "report_generator.py",
    "shodan_integration.py",
    "utils.py",
    "web_scanner.py"
)

foreach ($file in $streamlitFiles) {
    $path = "D:\CyberShieldAI\CyberShieldAI\$file"
    if (Test-Path $path) {
        try {
            Remove-Item $path -Force
            Write-Host "  [OK] Removed $file" -ForegroundColor Green
            $removed++
        } catch {
            Write-Host "  [FAIL] Failed to remove $file : $_" -ForegroundColor Red
            $errors++
        }
    }
}

# 2. Remove pages directory (old Streamlit pages)
Write-Host "`n[2/5] Removing old Streamlit pages directory..." -ForegroundColor Yellow

$pagesDir = "D:\CyberShieldAI\CyberShieldAI\pages"
if (Test-Path $pagesDir) {
    try {
        Remove-Item $pagesDir -Recurse -Force
        Write-Host "  [OK] Removed pages/" -ForegroundColor Green
        $removed++
    } catch {
        Write-Host "  [FAIL] Failed to remove pages/: $_" -ForegroundColor Red
        $errors++
    }
}

# 3. Remove __pycache__ directories
Write-Host "`n[3/5] Removing Python cache directories..." -ForegroundColor Yellow

$pycacheDirs = Get-ChildItem -Path "D:\CyberShieldAI\CyberShieldAI" -Recurse -Filter "__pycache__" -Directory -ErrorAction SilentlyContinue

foreach ($dir in $pycacheDirs) {
    try {
        Remove-Item $dir.FullName -Recurse -Force
        Write-Host "  [OK] Removed $($dir.FullName.Replace('D:\CyberShieldAI\CyberShieldAI\', ''))" -ForegroundColor Green
        $removed++
    } catch {
        Write-Host "  [FAIL] Failed to remove $($dir.Name): $_" -ForegroundColor Red
        $errors++
    }
}

# 4. Remove coverage and test artifacts
Write-Host "`n[4/5] Removing test coverage files..." -ForegroundColor Yellow

$testArtifacts = @(
    "D:\CyberShieldAI\CyberShieldAI\htmlcov",
    "D:\CyberShieldAI\CyberShieldAI\backend\htmlcov",
    "D:\CyberShieldAI\CyberShieldAI\coverage.xml",
    "D:\CyberShieldAI\CyberShieldAI\backend\coverage.xml",
    "D:\CyberShieldAI\CyberShieldAI\.coverage",
    "D:\CyberShieldAI\CyberShieldAI\backend\.coverage"
)

foreach ($artifact in $testArtifacts) {
    if (Test-Path $artifact) {
        try {
            Remove-Item $artifact -Recurse -Force
            $name = Split-Path $artifact -Leaf
            Write-Host "  [OK] Removed $name" -ForegroundColor Green
            $removed++
        } catch {
            Write-Host "  [FAIL] Failed to remove $(Split-Path $artifact -Leaf): $_" -ForegroundColor Red
            $errors++
        }
    }
}

# 5. Remove old database files (if using PostgreSQL now)
Write-Host "`n[5/5] Removing old SQLite database..." -ForegroundColor Yellow

$dbFiles = @(
    "D:\CyberShieldAI\CyberShieldAI\cybersec_platform.db",
    "D:\CyberShieldAI\CyberShieldAI\backend\cybersec_platform.db"
)

foreach ($db in $dbFiles) {
    if (Test-Path $db) {
        try {
            Remove-Item $db -Force
            Write-Host "  [OK] Removed $(Split-Path $db -Leaf)" -ForegroundColor Green
            $removed++
        } catch {
            Write-Host "  [FAIL] Failed to remove $(Split-Path $db -Leaf): $_" -ForegroundColor Red
            $errors++
        }
    }
}

# 6. Remove attached_assets directory (old screenshots/pastes)
Write-Host "`n[6/6] Removing attached assets..." -ForegroundColor Yellow

$attachedDir = "D:\CyberShieldAI\CyberShieldAI\attached_assets"
if (Test-Path $attachedDir) {
    try {
        Remove-Item $attachedDir -Recurse -Force
        Write-Host "  [OK] Removed attached_assets/" -ForegroundColor Green
        $removed++
    } catch {
        Write-Host "  [FAIL] Failed to remove attached_assets/: $_" -ForegroundColor Red
        $errors++
    }
}

# Summary
Write-Host "`n" + "=" * 70 -ForegroundColor Cyan
Write-Host "CLEANUP SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "Files/Directories Removed: $removed" -ForegroundColor Green
Write-Host "Errors: $errors" -ForegroundColor $(if ($errors -gt 0) { "Red" } else { "Green" })

# List remaining important files
Write-Host "`nRemaining Project Structure:" -ForegroundColor Cyan
Write-Host "  backend/          - FastAPI backend" -ForegroundColor White
Write-Host "  frontend/         - React frontend" -ForegroundColor White
Write-Host "  .github/          - CI/CD workflows" -ForegroundColor White
Write-Host "  docker-compose*   - Docker orchestration" -ForegroundColor White
Write-Host "  *.md              - Documentation" -ForegroundColor White

Write-Host "`nRemoved:" -ForegroundColor Cyan
Write-Host "  [X] Old Streamlit files (app.py, pages/, etc.)" -ForegroundColor Gray
Write-Host "  [X] Python cache (__pycache__/)" -ForegroundColor Gray
Write-Host "  [X] Test coverage files (htmlcov/, coverage.xml)" -ForegroundColor Gray
Write-Host "  [X] Old SQLite database" -ForegroundColor Gray
Write-Host "  [X] Attached assets" -ForegroundColor Gray

Write-Host "`n" + "=" * 70 -ForegroundColor Cyan

if ($errors -eq 0) {
    Write-Host "CLEANUP COMPLETED SUCCESSFULLY!" -ForegroundColor Green
} else {
    Write-Host "CLEANUP COMPLETED WITH $errors ERROR(S)" -ForegroundColor Yellow
}

Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host ""
