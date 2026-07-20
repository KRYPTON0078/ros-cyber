# Changelog

All notable changes to ROS Cyber are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-19

### Added
- Multi-service platform: ingestion API, policy engine, detection worker, SOC dashboard
- ROS2 fleet simulator and attack injector for lab scenarios
- YAML-based command policy engine with kill switch
- Rule-based + ML anomaly detection with MITRE ATT&CK and IEC 62443 mapping
- ROS/IoT security scanner CLI (`roscyber scan`)
- Docker Compose stack: PostgreSQL, Redis, Mosquitto, Prometheus, Grafana
- Vulnerable lab overlay (`docker-compose.vuln.yml`) with 6 documented findings
- Hardened deployment profile with SROS2 hardening guide
- Full CI/CD: lint, typecheck, 80% coverage gate, bandit, pip-audit
- SBOM generation on release
- Comprehensive documentation: requirements, architecture, ADRs, threat model, pentest report

## [0.1.1] - 2026-07-20

### Added
- Demo guide, troubleshooting guide, and API reference
- Local demo scripts for seeding telemetry and running attacks
- Dashboard polling endpoints for alerts, audit, and fleet

## [0.1.2] - 2026-07-21

### Added
- Real map view with battery legends
- Alert charts, filters, and acknowledgement flow
- Role-based session panel with token metadata
- Attack replay timeline and live log streaming
- CSV/JSON report exports and helper scripts

[0.1.2]: https://github.com/KRYPTON0078/ros-cyber/releases/tag/v0.1.2

[0.1.1]: https://github.com/KRYPTON0078/ros-cyber/releases/tag/v0.1.1

[0.1.0]: https://github.com/KRYPTON0078/ros-cyber/releases/tag/v0.1.0
