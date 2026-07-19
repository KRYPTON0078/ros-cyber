"""Redis client for event streams."""

import json
from typing import Any

import redis.asyncio as redis

from roscyber.shared.config import get_settings

_client: redis.Redis | None = None


async def get_redis() -> redis.Redis:
    global _client
    if _client is None:
        settings = get_settings()
        _client = redis.from_url(settings.redis_url, decode_responses=True)
    return _client


async def publish_event(stream: str, event: dict[str, Any]) -> str:
    client = await get_redis()
    payload = {k: json.dumps(v) if isinstance(v, (dict, list)) else str(v) for k, v in event.items()}
    msg_id = await client.xadd(stream, payload)
    return str(msg_id)


async def read_events(stream: str, last_id: str = "0", count: int = 10) -> list[tuple[str, dict[str, str]]]:
    client = await get_redis()
    result = await client.xread({stream: last_id}, count=count, block=1000)
    events: list[tuple[str, dict[str, str]]] = []
    for _stream_name, messages in result:
        for msg_id, data in messages:
            events.append((msg_id, data))
    return events
