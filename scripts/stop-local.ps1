# Stop ROS Cyber local dev processes (ports 8000-8002)
$ErrorActionPreference = "Stop"

$ports = @(8000, 8001, 8002)
foreach ($port in $ports) {
    $line = netstat -ano | findstr ":$port"
    if ($line) {
        $pid = ($line -split "\\s+")[-1]
        if ($pid -match "^[0-9]+$") {
            try {
                taskkill /PID $pid /F | Out-Null
                Write-Host "Stopped PID $pid on port $port" -ForegroundColor Yellow
            } catch {
                Write-Host "Failed to stop PID $pid on port $port" -ForegroundColor Red
            }
        }
    }
}
