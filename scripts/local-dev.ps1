# ROS Cyber - local dev without Docker (Windows-friendly)
# Uses SQLite + log files (no Redis/Postgres required for basic demo)
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example" -ForegroundColor Yellow
}

$python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $python) {
    Write-Host "Python not found in PATH." -ForegroundColor Red
    exit 1
}

try {
    & $python -m uvicorn --version | Out-Null
} catch {
    Write-Host "uvicorn is not installed for this Python." -ForegroundColor Red
    Write-Host "Run:" -ForegroundColor Yellow
    Write-Host ("  {0} -m pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -e .[dev]" -f $python) -ForegroundColor Yellow
    exit 1
}

$env:PYTHONPATH = "src"
$env:DATABASE_URL = "sqlite+aiosqlite:///./roscyber_local.db"
$env:REDIS_URL = "redis://localhost:6379/0"
$env:ROSCYBER_DISABLE_REDIS = "true"
$env:JWT_SECRET = "local-dev-secret-change-in-production-min-32-chars"
$env:ROSCYBER_PROFILE = "hardened"

$logDir = Join-Path $root "logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

Write-Host ""
Write-Host "ROS Cyber - Local Dev Mode (no Docker)" -ForegroundColor Cyan
Write-Host "Logs are written to: $logDir" -ForegroundColor DarkGray
Write-Host ""

$processes = @()

function Start-ServiceProcess {
    param(
        [string]$Name,
        [string]$App,
        [int]$Port
    )
    $log = Join-Path $logDir "$Name.log"
    $errLog = Join-Path $logDir "$Name.err.log"
    if (Test-Path $log) {
        try { Clear-Content $log } catch { }
    }
    if (Test-Path $errLog) {
        try { Clear-Content $errLog } catch { }
    }
    Write-Host "Starting $Name on :$Port..." -ForegroundColor Green
    $proc = Start-Process -FilePath $python -ArgumentList "-m", "uvicorn", $App, "--host", "0.0.0.0", "--port", "$Port" `
        -RedirectStandardOutput $log -RedirectStandardError $errLog -PassThru -WindowStyle Hidden
    $processes += $proc
}

Start-ServiceProcess -Name "ingestion" -App "roscyber.ingestion.app:app" -Port 8000
Start-ServiceProcess -Name "policy" -App "roscyber.policy.app:app" -Port 8001
Start-ServiceProcess -Name "dashboard" -App "roscyber.dashboard.app:app" -Port 8002

Start-Sleep -Seconds 2

Write-Host ""
Write-Host "Services starting. Open in browser:" -ForegroundColor Green
Write-Host "  SOC Dashboard : http://localhost:8002"
Write-Host "  Ingestion API : http://localhost:8000/docs"
Write-Host "  Policy Engine : http://localhost:8001/docs"
Write-Host ""
Write-Host "If nothing loads, check logs:" -ForegroundColor Yellow
Write-Host "  $logDir\\ingestion.log"
Write-Host "  $logDir\\policy.log"
Write-Host "  $logDir\\dashboard.log"
Write-Host ""
Write-Host "Demo login: operator / operator123!" -ForegroundColor Yellow
Write-Host "Press Ctrl+C to stop all services." -ForegroundColor DarkGray
Write-Host ""

try {
    while ($true) { Start-Sleep -Seconds 5 }
}
finally {
    Write-Host "Stopping services..." -ForegroundColor Yellow
    foreach ($proc in $processes) {
        try { Stop-Process -Id $proc.Id -Force } catch { }
    }
}
