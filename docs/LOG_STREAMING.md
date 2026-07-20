# Live Log Streaming

The dashboard consumes Server-Sent Events for alert and audit logs:

- `GET /api/v1/stream/alerts`
- `GET /api/v1/stream/audit`

These streams emit JSON payloads every time new records are written.
