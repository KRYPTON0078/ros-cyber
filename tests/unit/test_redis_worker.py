"""Tests for redis client."""

from unittest.mock import AsyncMock, patch

import pytest

from roscyber.shared.redis_client import publish_event, read_events


@pytest.mark.asyncio
async def test_publish_event():
    mock_redis = AsyncMock()
    mock_redis.xadd = AsyncMock(return_value="1234-0")
    with patch("roscyber.shared.redis_client.get_redis", AsyncMock(return_value=mock_redis)):
        msg_id = await publish_event("test-stream", {"event_type": "test", "robot_id": "r1"})
        assert msg_id == "1234-0"


@pytest.mark.asyncio
async def test_read_events():
    mock_redis = AsyncMock()
    mock_redis.xread = AsyncMock(return_value=[("test-stream", [("1-0", {"a": "b"})])])
    with patch("roscyber.shared.redis_client.get_redis", AsyncMock(return_value=mock_redis)):
        events = await read_events("test-stream")
        assert len(events) == 1
        assert events[0][0] == "1-0"
