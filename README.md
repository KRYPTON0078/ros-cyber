# ROS Cyber

[![CI](https://github.com/KRYPTON0078/ros-cyber/actions/workflows/ci.yml/badge.svg)](https://github.com/KRYPTON0078/ros-cyber/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Coverage](https://img.shields.io/badge/coverage-80%25+-green.svg)](tests/)

**Production-grade ROS2 cyber-physical security platform** — policy-gated robot commands, real-time threat detection, offensive security lab, and SOC dashboard.

> Built by **Magne Dina Neves** — international robotics competition winner. ROS Cyber applies competition-grade systems thinking to securing autonomous robot fleets.

## Features

- **Policy Engine** — YAML-defined rules gate every `cmd_vel` command (velocity limits, geofencing, kill switch)
- **Detection Pipeline** — Redis Streams → async worker → PostgreSQL alerts with MITRE ATT&CK + IEC 62443 mapping
- **SOC Dashboard** — Live WebSocket alerts, fleet GPS map, audit log, compliance panel
- **Security Scanner** — `roscyber scan` checks DDS exposure, default creds, cleartext APIs, SROS2 status
- **Offensive Lab** — Isolated vulnerable Docker profile with 6 documented pentest findings + PoC scripts
- **Hardened Profile** — Production deployment template with SROS2 guide and full remediations
- **Full SDLC** — 80% test coverage, CI/CD, ADRs, threat model, structured logging, Prometheus metrics

## Quick Start

### Option A — Docker (full stack, recommended)

**Requires [Docker Desktop for Windows](https://docs.docker.com/desktop/setup/install/windows-install/)** installed and running.

```powershell
git clone https://github.com/KRYPTON0078/ros-cyber.git
cd ros-cyber
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -e ".[dev]"
.\scripts\docker-up.ps1
```

Or with Make (if Docker is in PATH): `make docker-up`

### Option B — Local dev without Docker (Windows)

If Docker is not installed, use the PowerShell script:

```powershell
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -e ".[dev]"
.\scripts\local-dev.ps1
```

This starts Ingestion API, Policy Engine, and SOC Dashboard on ports 8000–8002 using SQLite.

### Local Demo (no Docker)

```powershell
.\scripts\demo-seed.ps1     # seed telemetry + policy decisions
.\scripts\demo-attack.ps1   # run attack simulator
```

CLI alternative:
```powershell
roscyber demo-seed
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
| [DEMO_GUIDE.md](docs/DEMO_GUIDE.md) | Step-by-step demo instructions |
| [API_REFERENCE.md](docs/API_REFERENCE.md) | Quick API reference |
| [ALERT_RULES.md](docs/ALERT_RULES.md) | Alert rules and severities |
| [LOCAL_MODE.md](docs/LOCAL_MODE.md) | Local mode limitations |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common issues and fixes |
| [ATTACK_REPLAY.md](docs/ATTACK_REPLAY.md) | Replay timeline behavior |
| [LOG_STREAMING.md](docs/LOG_STREAMING.md) | SSE log streaming |
| [ROLE_BASED_UI.md](docs/ROLE_BASED_UI.md) | Role-based UI behavior |
| [EXPORTS.md](docs/EXPORTS.md) | Alert and audit exports |
| [TOKENS.md](docs/TOKENS.md) | REST auth tokens |
| [CHARTS.md](docs/CHARTS.md) | Alert charting |
| [MAP.md](docs/MAP.md) | Fleet map and marker legend |
| [SCRIPTS.md](docs/SCRIPTS.md) | Helper scripts |
| [FLEET_HEALTH.md](docs/FLEET_HEALTH.md) | Fleet health summary |
| [ALERT_FILTERS.md](docs/ALERT_FILTERS.md) | Alert severity filters |
| [AUDIT_FILTERS.md](docs/AUDIT_FILTERS.md) | Audit log filters |

## License

MIT — see [LICENSE](LICENSE)

## Security

See [SECURITY.md](SECURITY.md) for responsible disclosure policy.
