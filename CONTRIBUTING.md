# Contributing to ROS Cyber

Thank you for your interest in contributing to ROS Cyber!

## Development Setup

```powershell
git clone https://github.com/KRYPTON0078/ros-cyber.git
cd ros-cyber
pip install -e ".[dev]"
pre-commit install
cp .env.example .env
```

## Running Locally

```powershell
make docker-up      # Start full stack
make test           # Run tests with coverage
make lint           # Ruff + Black + Mypy
make scan           # Run security scanner
```

## Commit Conventions

We use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation
- `test:` tests
- `ci:` CI/CD changes
- `chore:` maintenance

## Pull Request Checklist

- [ ] Tests pass (`make test`)
- [ ] Lint passes (`make lint`)
- [ ] Documentation updated if needed
- [ ] No secrets committed
- [ ] ADR added for architectural changes

## Code Style

- Python 3.11+, type hints required
- Line length: 100 (Black + Ruff)
- Strict mypy on `src/roscyber`
