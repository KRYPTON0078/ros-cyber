# ROS Cyber

[![CI](https://github.com/YOUR_USERNAME/ros-cyber/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/ros-cyber/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Coverage](https://img.shields.io/badge/coverage-80%25+-green.svg)](tests/)

**Production-grade ROS2 cyber-physical security platform** — policy-gated robot commands, real-time threat detection, offensive security lab, and SOC dashboard.

> Built by **Magna Dina Neves** — international robotics competition winner. ROS Cyber applies competition-grade systems thinking to securing autonomous robot fleets.

## Features

- **Policy Engine** — YAML-defined rules gate every `cmd_vel` command (velocity limits, geofencing, kill switch)
- **Detection Pipeline** — Redis Streams → async worker → PostgreSQL alerts with MITRE ATT&CK + IEC 62443 mapping
- **SOC Dashboard** — Live WebSocket alerts, fleet GPS map, audit log, compliance panel
- **Security Scanner** — `roscyber scan` checks DDS exposure, default creds, cleartext APIs, SROS2 status
- **Offensive Lab** — Isolated vulnerable Docker profile with 6 documented pentest findings + PoC scripts
- **Hardened Profile** — Production deployment template with SROS2 guide and full remediations
- **Full SDLC** — 80% test coverage, CI/CD, ADRs, threat model, structured logging, Prometheus metrics

## Quick Start

```powershell
# Clone and configure
git clone https://github.com/YOUR_USERNAME/ros-cyber.git
cd ros-cyber
cp .env.example .env

# Start full stack (hardened profile)
make docker-up

# Open services
# SOC Dashboard:  http://localhost:8002
# Ingestion API:  http://localhost:8000/docs
# Policy Engine:  http://localhost:8001/docs
# Grafana:        http://localhost:3000  (admin / roscyber)
# Prometheus:     http://localhost:9091
```

## Demo Credentials

| User | Password | Role |
|------|----------|------|
| admin | admin123! | admin |
| operator | operator123! | operator |

## Architecture

```
ROS2 Fleet → Ingestion API → Redis Streams → Detection Worker → Alerts → Dashboard
                    ↓
              Policy Engine → Audit Log (PostgreSQL)
                    ↓
              Approved Commands → Robot Motion
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for full C4 diagrams.

## Offensive Lab (Isolated Testing Only)

```powershell
# WARNING: Intentionally vulnerable — isolated network only
make docker-vuln
make demo-attack
```

Findings documented in [docs/PENTEST_REPORT.md](docs/PENTEST_REPORT.md).

## Development

```powershell
pip install -e ".[dev]"
make test       # pytest with 80% coverage gate
make lint       # ruff + black + mypy
make scan       # run security scanner
pre-commit install
```

## Project Structure

```
ros-cyber/
├── src/roscyber/       # Python platform (ingestion, policy, detection, dashboard, scanner)
├── ros2_ws/            # ROS2 fleet simulator + attack injector
├── policies/           # YAML command policies
├── labs/poc/           # Pentest proof-of-concept scripts
├── infra/              # Docker, Prometheus, Grafana configs
├── docs/               # Requirements, architecture, ADRs, threat model
└── tests/              # Unit, integration, e2e tests
```

## Documentation

| Document | Description |
|----------|-------------|
| [REQUIREMENTS.md](docs/REQUIREMENTS.md) | Functional + non-functional requirements |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design and data flows |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | STRIDE analysis |
| [PENTEST_REPORT.md](docs/PENTEST_REPORT.md) | 6 findings with CVSS and PoCs |
| [HARDENING_GUIDE.md](docs/HARDENING_GUIDE.md) | SROS2, TLS, production checklist |

## License

MIT — see [LICENSE](LICENSE)

## Security

See [SECURITY.md](SECURITY.md) for responsible disclosure policy.
