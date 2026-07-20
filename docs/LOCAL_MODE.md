# Local Mode (No Docker)

Local mode runs Ingestion, Policy, and Dashboard with SQLite and disables Redis.

## What works
- Telemetry ingestion
- Policy decisions and audit log
- Dashboard polling endpoints
- SSE log streaming from SQLite-backed events

## Limitations
- Live alert feed uses polling (no Redis streams)
- Detection worker is not active
