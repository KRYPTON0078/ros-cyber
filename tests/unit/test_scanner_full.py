"""Scanner tests with mocked HTTP."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from roscyber.scanner.scanner import SecurityScanner, run_scan


@pytest.mark.asyncio
async def test_scanner_full_run_mocked(monkeypatch):
    monkeypatch.setenv("ROSCYBER_PROFILE", "vulnerable")
    from roscyber.shared.config import get_settings

    get_settings.cache_clear()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"access_token": "test-token"}

    mock_list_response = MagicMock()
    mock_list_response.status_code = 200
    mock_list_response.json.return_value = [{"firmware_version": "1.0.0"}]

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.get = AsyncMock(return_value=mock_list_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("roscyber.scanner.scanner.httpx.AsyncClient", return_value=mock_client):
        with patch("roscyber.scanner.scanner.socket.create_connection", side_effect=OSError):
            result = await run_scan("localhost")
    assert result.target == "localhost"
    assert any(f.check_id == "IOT-002" for f in result.findings)
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_scanner_default_creds_finding(monkeypatch):
    monkeypatch.setenv("ROSCYBER_PROFILE", "hardened")
    from roscyber.shared.config import get_settings

    get_settings.cache_clear()
    scanner = SecurityScanner("localhost")
    result = type("R", (), {"findings": []})()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("roscyber.scanner.scanner.httpx.AsyncClient", return_value=mock_client):
        await scanner._check_api_default_creds(result)
    assert any(f.check_id == "IOT-001" for f in result.findings)
    get_settings.cache_clear()
