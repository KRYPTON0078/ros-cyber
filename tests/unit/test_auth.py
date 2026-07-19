"""Unit tests for JWT auth."""

import os

import pytest
from fastapi import HTTPException

from roscyber.ingestion.auth import Role, create_access_token, decode_token, hash_password, verify_password


@pytest.fixture(autouse=True)
def setup_env():
    os.environ["JWT_SECRET"] = "test-secret-key-for-unit-tests-min-32-chars"
    os.environ["ROSCYBER_PROFILE"] = "hardened"


def test_create_and_decode_token():
    token = create_access_token("operator", Role.OPERATOR)
    payload = decode_token(token)
    assert payload.sub == "operator"
    assert payload.role == Role.OPERATOR


def test_invalid_token_rejected():
    with pytest.raises(HTTPException):
        decode_token("invalid.token.here")


def test_password_verification():
    hashed = hash_password("testpass")
    assert verify_password("testpass", hashed) is True
    assert verify_password("wrong", hashed) is False


def test_vuln_alg_none_bypass():
    os.environ["ROSCYBER_PROFILE"] = "vulnerable"
    token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJhZG1pbiJ9."
    payload = decode_token(token, allow_vuln_bypass=True)
    assert payload.sub == "attacker"
    assert payload.role == Role.ADMIN
