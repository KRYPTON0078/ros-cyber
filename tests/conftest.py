"""Pytest configuration and shared fixtures."""

import os
from unittest.mock import AsyncMock

import pytest


@pytest.fixture(autouse=True)
def test_env(monkeypatch):
    from roscyber.shared.config import get_settings
    from roscyber.shared.database import reset_engine

    monkeypatch.setenv("JWT_SECRET", "test-secret-key-for-pytest-suite-min-32-chars")
    monkeypatch.setenv("ROSCYBER_PROFILE", "hardened")
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    get_settings.cache_clear()
    reset_engine()
    yield
    get_settings.cache_clear()
    reset_engine()


@pytest.fixture
def mock_redis(monkeypatch):
    mock = AsyncMock(return_value="0-1")
    targets = [
        "roscyber.shared.redis_client.publish_event",
        "roscyber.ingestion.app.publish_event",
        "roscyber.policy.app.publish_event",
    ]
    for target in targets:
        monkeypatch.setattr(target, mock)
    return mock
