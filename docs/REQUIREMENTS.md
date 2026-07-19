# Requirements Specification — ROS Cyber v0.1

## 1. Overview

ROS Cyber is a production-grade cyber-physical security platform for ROS2 robot fleets.

**Author:** Magna Dina Neves — International Robotics Competition Winner

## 2. Functional Requirements

| ID | Requirement | Acceptance Criteria |
|----|-------------|---------------------|
| FR-01 | Ingest robot telemetry | POST `/v1/telemetry` persists GPS, IMU, battery, motor data |
| FR-02 | Authenticate operators | JWT token issued on valid login; rejected on invalid |
| FR-03 | Gate robot commands | Policy engine approves/denies cmd_vel before execution |
| FR-04 | Detect threats | Detection worker raises alerts within 5s of attack event |
| FR-05 | Display SOC dashboard | Live alerts, fleet map, audit log at port 8002 |
| FR-06 | Scan misconfigurations | `roscyber scan` produces JSON + Markdown report |
| FR-07 | Emergency kill switch | Admin can halt all motion via `/v1/kill-switch/on` |
| FR-08 | Vulnerable lab profile | Isolated docker profile with 6+ reproducible findings |
| FR-09 | Hardened profile | All documented findings remediated in hardened mode |

## 3. Non-Functional Requirements

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-01 | Test coverage | ≥ 80% on `src/roscyber` |
| NFR-02 | API response time | < 200ms p95 for telemetry ingestion |
| NFR-03 | Observability | Prometheus metrics on all services |
| NFR-04 | Reproducibility | `docker compose up` healthy in < 5 minutes |
| NFR-05 | Security scanning | Bandit + pip-audit in CI on every PR |
| NFR-06 | Documentation | Architecture, threat model, pentest report complete |

## 4. Out of Scope (v0.1)

- Kubernetes/Helm deployment
- Native ROS2 SROS2 keystore generation (documented guide only)
- Multi-tenant SaaS billing
- Mobile app
