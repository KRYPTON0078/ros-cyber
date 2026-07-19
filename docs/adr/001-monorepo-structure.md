# ADR-001: Monorepo Structure with src-layout

## Status

Accepted

## Context

ROS Cyber comprises multiple services (ingestion, policy, detection, dashboard, scanner) that share models, config, and utilities. We need a structure that supports:

- Single package installation for all services
- Strict typing with mypy
- Docker multi-service deployment from one repo

## Decision

Use a **Python monorepo** with `src/roscyber/` layout:

- Subpackages: `ingestion`, `policy`, `detection`, `dashboard`, `scanner`, `shared`, `cli`
- Single `pyproject.toml` with `[project.scripts]` for CLI
- Each service launched via `uvicorn roscyber.<service>.app:app`

## Consequences

- **Positive:** Shared code without duplication; one CI pipeline; one version number
- **Negative:** All services deploy together in v0.1 (acceptable for portfolio/lab)
- **Future:** Split into separate repos or microservice images per ADR if scale demands
