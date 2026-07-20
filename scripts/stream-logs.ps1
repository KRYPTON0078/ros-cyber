param(
    [string]$BaseUrl = "http://localhost:8002",
    [ValidateSet("alerts","audit")]
    [string]$Stream = "audit"
)

$url = "$BaseUrl/api/v1/stream/$Stream"
Write-Host "Streaming $Stream events from $url"
curl $url
