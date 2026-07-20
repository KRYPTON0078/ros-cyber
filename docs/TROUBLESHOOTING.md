# Troubleshooting

## Local demo shows "Waiting for events"

Local mode disables Redis by default. Alert feed uses DB polling every 5 seconds, so you
should see alerts after you run `demo-seed.ps1` or `demo-attack.ps1`.

## Ports already in use

Find the PID and stop it:

```powershell
netstat -ano | findstr ":8000"
taskkill /PID <PID> /F
```

## Docker not found

Install Docker Desktop for Windows:
https://docs.docker.com/desktop/setup/install/windows-install/

## CI lint errors

Run locally:

```powershell
ruff check src tests
black --check src tests
mypy src/roscyber
```
