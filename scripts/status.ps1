# ROS Cyber status check
$ErrorActionPreference = "Stop"

$endpoints = @(
    "http://localhost:8000/health",
    "http://localhost:8001/health",
    "http://localhost:8002/health"
)

foreach ($url in $endpoints) {
    try {
        $resp = Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 3
        Write-Host "$url -> $($resp.status)" -ForegroundColor Green
    } catch {
        Write-Host "$url -> DOWN" -ForegroundColor Red
    }
}
