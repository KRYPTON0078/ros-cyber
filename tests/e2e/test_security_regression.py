"""E2E security regression: vuln vs hardened profiles."""

import os

import pytest
from fastapi import HTTPException

from roscyber.ingestion.auth import Role, decode_token
from roscyber.policy.engine import PolicyEngine


def test_vuln_profile_allows_injection(tmp_path):
    os.environ["ROSCYBER_PROFILE"] = "vulnerable"
    engine = PolicyEngine(policies_dir=str(tmp_path))
    decision = engine.evaluate_command({"linear_x": 0.1, "params": {"exec": "; rm -rf /"}})
    assert decision.approved is True


def test_hardened_profile_blocks_speed(tmp_path):
    os.environ["ROSCYBER_PROFILE"] = "hardened"
    policy_file = tmp_path / "p.yaml"
    policy_file.write_text(
        "rules:\n  - name: max_linear_velocity\n    type: field_limit\n    field: linear.x\n    max: 1.5\n",
        encoding="utf-8",
    )
    engine = PolicyEngine(policies_dir=str(tmp_path))
    decision = engine.evaluate_command({"linear_x": 2.5})
    assert decision.approved is False


def test_jwt_alg_none_only_in_vuln_mode():
    os.environ["ROSCYBER_PROFILE"] = "vulnerable"
    token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJhZG1pbiJ9."
    payload = decode_token(token, allow_vuln_bypass=True)
    assert payload.role == Role.ADMIN

    os.environ["ROSCYBER_PROFILE"] = "hardened"
    with pytest.raises(HTTPException):
        decode_token(token, allow_vuln_bypass=False)
