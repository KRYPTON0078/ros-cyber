# Alert Rules (v0.1)

| Rule | Trigger | Severity |
|------|---------|----------|
| auth_brute_force | 5+ failed logins in 60s | High |
| telemetry_flood | >50 telemetry messages/sec | Medium |
| gps_anomaly | Impossible GPS jump | Critical |
| policy_violation | Command denied by policy | High |
| kill_switch | Kill switch activated | Critical |
| ml_anomaly | Z-score threshold exceeded | High |

## Operator Workflow

- Validate alert metadata and severity.
- Cross-check against MITRE technique.
- Document response in incident timeline.
- Acknowledge alerts in the SOC dashboard.
