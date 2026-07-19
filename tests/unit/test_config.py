"""Unit tests for shared config."""

from roscyber.shared.config import Settings, get_settings


def test_settings_defaults():
    settings = Settings()
    assert settings.app_name == "ROS Cyber"
    assert settings.jwt_algorithm == "HS256"


def test_get_settings_cached():
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2
