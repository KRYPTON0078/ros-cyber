# ROS Cyber — stop Docker stack
Set-Location (Split-Path $PSScriptRoot -Parent)
$docker = Get-Command docker -ErrorAction SilentlyContinue
if (-not $docker) {
    Write-Host "Docker not found." -ForegroundColor Red
    exit 1
}
docker compose down -v
