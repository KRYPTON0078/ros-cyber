"""Unit tests for security scanner."""

import pytest

from roscyber.scanner.scanner import ScanFinding, ScanResult, SecurityScanner


def test_scan_result_markdown():
    result = ScanResult(
        target="lab",
        findings=[
            ScanFinding("IOT-001", "Test Finding", "HIGH", "desc", "fix"),
        ],
    )
    md = result.to_markdown()
    assert "Test Finding" in md
    assert result.to_dict()["findings_count"] == 1
