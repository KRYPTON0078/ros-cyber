# API Reference (Short)

## Ingestion API (8000)

- `POST /v1/auth/token`
- `POST /v1/telemetry`
- `GET /v1/robots/{robot_id}/telemetry`
- `POST /v1/events`
- `GET /health`

## Policy Engine (8001)

- `POST /v1/commands/evaluate`
- `POST /v1/kill-switch/{state}`
- `POST /v1/policies/reload`
- `GET /health`

## Dashboard API (8002)

- `GET /api/v1/summary`
- `GET /api/v1/alerts`
- `GET /api/v1/audit`
- `GET /api/v1/fleet`
- `GET /api/v1/report/alerts.csv`
- `GET /api/v1/report/alerts.json`
- `GET /api/v1/report/audit.csv`
- `GET /api/v1/report/audit.json`
