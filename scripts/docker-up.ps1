# ROS Cyber - start full Docker stack (requires Docker Desktop)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

$docker = Get-Command docker -ErrorAction SilentlyContinue
if (-not $docker) {
    Write-Host ""
    Write-Host "Docker is not installed or not in PATH." -ForegroundColor Red
    Write-Host ""
    Write-Host "Install Docker Desktop for Windows:" -ForegroundColor Yellow
    Write-Host "  https://docs.docker.com/desktop/setup/install/windows-install/"
    Write-Host ""
    Write-Host "After install: restart terminal, open Docker Desktop, then run:" -ForegroundColor Yellow
    Write-Host "  .\scripts\docker-up.ps1"
    Write-Host ""
    Write-Host "Or run without Docker (local Python mode):" -ForegroundColor Cyan
    Write-Host "  .\scripts\local-dev.ps1"
    Write-Host ""
    exit 1
}

Write-Host "Starting ROS Cyber stack..." -ForegroundColor Cyan
docker compose up -d --build
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "ROS Cyber is running:" -ForegroundColor Green
Write-Host "  SOC Dashboard : http://localhost:8002"
Write-Host "  Ingestion API : http://localhost:8000/docs"
Write-Host "  Policy Engine : http://localhost:8001/docs"
Write-Host "  Grafana       : http://localhost:3000  (admin / roscyber)"
Write-Host ""
