# ROS Cyber Demo Guide

## Local Demo (no Docker)

1. Start services:
   ```powershell
   .\scripts\local-dev.ps1
   ```
2. Seed telemetry and policy decisions:
   ```powershell
   .\scripts\demo-seed.ps1
   ```
3. Run the attack simulator:
   ```powershell
   .\scripts\demo-attack.ps1
   ```
4. Open the SOC dashboard:
   - http://localhost:8002

## Full Demo (Docker)

1. Start Docker stack:
   ```powershell
   .\scripts\docker-up.ps1
   ```
2. Start vulnerable lab overlay:
   ```powershell
   docker compose -f docker-compose.yml -f docker-compose.vuln.yml up -d --build
   ```
3. Run attack simulator:
   ```powershell
   python .\ros2_ws\scripts\attack_injector.py
   ```

## What to Watch

- Fleet map updates with telemetry
- Audit log shows allow/deny decisions
- Alert feed populates during attack demo
