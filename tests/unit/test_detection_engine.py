"""Unit tests for detection engine."""

import os

import pytest

from roscyber.detection.engine import DetectionEngine
from roscyber.shared.models import AlertSeverity


@pytest.fixture
def detector():
    os.environ["TELEMETRY_FLOOD_THRESHOLD"] = "50"
    os.environ["GPS_JUMP_THRESHOLD_M"] = "500"
    return DetectionEngine()


def test_brute_force_detection(detector):
    results = []
    for _ in range(5):
        results.extend(detector.process_event({"event_type": "auth_failure", "source_ip": "10.0.0.1"}))
    assert any(r.event_type == "auth_brute_force" for r in results)


def test_policy_violation_detection(detector):
    results = detector.process_event(
        {"event_type": "policy_violation", "robot_id": "robot-alpha", "reason": "speed limit"}
    )
    assert len(results) == 1
    assert results[0].severity == AlertSeverity.HIGH


def test_gps_anomaly_detection(detector):
    detector.process_event(
        {"event_type": "telemetry", "robot_id": "r1", "latitude": 14.6, "longitude": 120.98}
    )
    results = detector.process_event(
        {"event_type": "telemetry", "robot_id": "r1", "latitude": 40.71, "longitude": -74.0}
    )
    assert any(r.event_type == "gps_anomaly" for r in results)


def test_mitre_mapping_in_results(detector):
    results = detector.process_event(
        {"event_type": "policy_violation", "robot_id": "r1", "reason": "test"}
    )
    assert results[0].raw_event  # includes mitre after processing
