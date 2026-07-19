# Architecture — ROS Cyber

## Context Diagram

ROS Cyber sits between robot fleets (ROS2) and security operations teams, providing command gating, telemetry ingestion, threat detection, and compliance scanning.

## Containers

| Container | Technology | Port | Responsibility |
|-----------|-----------|------|----------------|
| ingestion | FastAPI | 8000 | Telemetry ingress, auth, OpenAPI |
| policy | FastAPI | 8001 | Command validation, kill switch, audit |
| detection | Python asyncio | — | Redis stream consumer, alert generation |
| dashboard | FastAPI + WebSocket | 8002 | SOC UI |
| postgres | PostgreSQL 16 | 5432 | Persistent storage |
| redis | Redis 7 | 6379 | Event streams |
| mosquitto | Eclipse Mosquitto | 1883 | MQTT messaging |
| prometheus | Prometheus | 9091 | Metrics collection |
| grafana | Grafana | 3000 | Metrics visualization |
| ros2-fleet | ROS2 Humble | — | Simulated robot telemetry |
| rosbridge | rosbridge_suite | 9090 | WebSocket ROS bridge |

## Data Flows

1. **Telemetry:** Robot → Ingestion API → PostgreSQL + Redis Stream → Detection Worker → Alert → Dashboard
2. **Commands:** Operator → Policy Engine → (approve/deny) → Audit Log → Robot
3. **Scanning:** CLI → Target APIs/ports → Report → Dashboard compliance panel

## Trust Boundaries

- **Robot VLAN:** ROS2 nodes, rosbridge (untrusted input)
- **Platform VLAN:** ingestion, policy, detection, dashboard (trusted)
- **Ops VLAN:** Grafana, Prometheus, SOC analysts

## Security Controls

- JWT authentication with RBAC (admin/operator)
- Rate limiting on auth and telemetry endpoints (hardened)
- YAML policy engine for command validation
- Structured audit logging with correlation IDs
- Network isolation for vulnerable lab profile

See [THREAT_MODEL.md](THREAT_MODEL.md) for STRIDE analysis.
