"""Unit tests for MITRE mapper."""

from roscyber.detection.mitre_map import map_techniques


def test_policy_violation_maps_to_t0855():
    mitre, iec = map_techniques("policy_violation")
    assert mitre == "T0855"
    assert iec == "SR 3.3"


def test_auth_brute_force_mapping():
    mitre, iec = map_techniques("auth_brute_force")
    assert mitre == "T1110.001"
    assert iec == "SR 1.1"


def test_unknown_event_defaults():
    mitre, iec = map_techniques("unknown_event")
    assert mitre == "T1190"
    assert iec == "SR 3.3"
