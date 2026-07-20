$alerts = "roscyber_alerts.csv"
$audit = "roscyber_audit.csv"

if (Test-Path $alerts) { Start-Process $alerts }
if (Test-Path $audit) { Start-Process $audit }

Write-Host "Opened reports if present."
