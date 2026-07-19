.PHONY: dev install lint test docker-up docker-down docker-vuln scan demo-attack migrate

install:
	pip install -e ".[dev]"

dev:
	uvicorn roscyber.ingestion.app:app --host 0.0.0.0 --port 8000 --reload

lint:
	ruff check src tests
	black --check src tests
	mypy src/roscyber

format:
	ruff check --fix src tests
	black src tests

test:
	pytest tests/ --cov=roscyber --cov-report=term-missing --cov-fail-under=80

test-quick:
	pytest tests/unit -q

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down -v

docker-vuln:
	docker compose -f docker-compose.yml -f docker-compose.vuln.yml up -d --build

scan:
	roscyber scan --target localhost --output reports/scan.json --markdown reports/scan.md

demo-attack:
	python scripts/demo_attack.py

migrate:
	alembic upgrade head
