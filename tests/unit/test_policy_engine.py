"""Unit tests for policy engine."""

import os

import pytest

from roscyber.policy.engine import PolicyEngine


@pytest.fixture
def engine(tmp_path):
    policy_file = tmp_path / "cmd_vel.yaml"
    policy_file.write_text(
        """
rules:
  - name: max_linear_velocity
    type: field_limit
    field: linear.x
    max: 1.5
    action: deny
  - name: max_angular_velocity
    type: field_limit
    field: angular.z
    max: 2.0
    action: deny
""",
        encoding="utf-8",
    )
    os.environ["ROSCYBER_PROFILE"] = "hardened"
    return PolicyEngine(policies_dir=str(tmp_path))


def test_approve_safe_command(engine):
    decision = engine.evaluate_command({"linear_x": 0.5, "angular_z": 0.1})
    assert decision.approved is True


def test_deny_excessive_linear_velocity(engine):
    decision = engine.evaluate_command({"linear_x": 2.5, "angular_z": 0.0})
    assert decision.approved is False
    assert "linear.x" in decision.reason


def test_deny_excessive_angular_velocity(engine):
    decision = engine.evaluate_command({"linear_x": 0.0, "angular_z": 3.0})
    assert decision.approved is False


def test_kill_switch_blocks_all(engine):
    engine.set_kill_switch(True)
    decision = engine.evaluate_command({"linear_x": 0.1, "angular_z": 0.0})
    assert decision.approved is False
    assert "Kill switch" in decision.reason


def test_geofence_violation(engine, tmp_path):
    policy_file = tmp_path / "geo.yaml"
    policy_file.write_text(
        """
rules:
  - name: fence
    type: geofence
    bounds: { lat_min: 14.0, lat_max: 15.0, lon_min: 120.0, lon_max: 121.0 }
""",
        encoding="utf-8",
    )
    eng = PolicyEngine(policies_dir=str(tmp_path))
    decision = eng.evaluate_command({"latitude": 50.0, "longitude": 120.5, "linear_x": 0.1})
    assert decision.approved is False
