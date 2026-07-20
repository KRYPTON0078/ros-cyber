param(
    [string]$BaseUrl = "http://localhost:8002",
    [ValidateSet("csv","json")]
    [string]$Format = "csv"
)

$outFile = "roscyber_alerts.$Format"
$url = "$BaseUrl/api/v1/report/alerts.$Format"
Invoke-WebRequest -Uri $url -OutFile $outFile | Out-Null
Write-Host "Saved $outFile"
