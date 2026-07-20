# ROS Cyber demo seed (local mode)
$ErrorActionPreference = "Stop"

$tokenResp = Invoke-RestMethod -Method Post -Uri http://localhost:8000/v1/auth/token `
    -Body (@{username="operator";password="operator123!"} | ConvertTo-Json) `
    -ContentType "application/json"

$token = $tokenResp.access_token

Write-Host "Token acquired. Seeding telemetry..." -ForegroundColor Green

for ($i = 0; $i -lt 5; $i++) {
    $lat = 14.60 + ($i * 0.0005)
    $lon = 120.98 + ($i * 0.0005)
    Invoke-RestMethod -Method Post -Uri http://localhost:8000/v1/telemetry `
        -Headers @{Authorization="Bearer $token"} `
        -Body (@{
            robot_id="robot-alpha";
            latitude=$lat;
            longitude=$lon;
            battery_pct=92;
            motor_rpm=700
        } | ConvertTo-Json) `
        -ContentType "application/json" | Out-Null
}

Write-Host "Sending policy commands..." -ForegroundColor Green

Invoke-RestMethod -Method Post -Uri http://localhost:8001/v1/commands/evaluate `
    -Headers @{Authorization="Bearer $token"} `
    -Body (@{robot_id="robot-alpha";command_type="cmd_vel";linear_x=0.6;angular_z=0.2} | ConvertTo-Json) `
    -ContentType "application/json" | Out-Null

Invoke-RestMethod -Method Post -Uri http://localhost:8001/v1/commands/evaluate `
    -Headers @{Authorization="Bearer $token"} `
    -Body (@{robot_id="robot-alpha";command_type="cmd_vel";linear_x=2.2;angular_z=0.4} | ConvertTo-Json) `
    -ContentType "application/json" | Out-Null

Write-Host "Demo data seeded. Open http://localhost:8002" -ForegroundColor Cyan
