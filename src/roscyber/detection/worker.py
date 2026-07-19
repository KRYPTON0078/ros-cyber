"""Async detection worker consuming Redis streams."""

import asyncio
import json

from roscyber.detection.engine import DetectionEngine
from roscyber.detection.mitre_map import map_techniques
from roscyber.shared.config import get_settings
from roscyber.shared.database import get_session_factory, init_db
from roscyber.shared.logging import configure_logging, get_logger
from roscyber.shared.metrics import ALERTS_RAISED
from roscyber.shared.models import SecurityAlert
from roscyber.shared.redis_client import get_redis, publish_event

configure_logging()
logger = get_logger("detection_worker")


async def run_worker() -> None:
    settings = get_settings()
    await init_db()
    engine = DetectionEngine()
    redis = await get_redis()
    last_id = "0-0"
    factory = get_session_factory()

    logger.info("detection_worker_started", stream=settings.detection_stream)

    while True:
        try:
            result = await redis.xread({settings.detection_stream: last_id}, count=10, block=2000)
            if not result:
                continue
            for _stream, messages in result:
                for msg_id, data in messages:
                    last_id = msg_id
                    event = {k: _parse_value(v) for k, v in data.items()}
                    detections = engine.process_event(event)
                    for det in detections:
                        mitre, iec = map_techniques(det.event_type)
                        async with factory() as session:
                            alert = SecurityAlert(
                                robot_id=det.robot_id,
                                severity=det.severity.value,
                                title=det.title,
                                description=det.description,
                                mitre_technique=mitre,
                                iec_control=iec,
                                raw_event=det.raw_event,
                            )
                            session.add(alert)
                            await session.commit()
                            await session.refresh(alert)
                        ALERTS_RAISED.labels(severity=det.severity.value).inc()
                        await publish_event(
                            settings.alert_stream,
                            {
                                "alert_id": alert.id,
                                "severity": det.severity.value,
                                "title": det.title,
                                "robot_id": det.robot_id,
                                "mitre": mitre,
                            },
                        )
                        logger.info("alert_raised", alert_id=alert.id, title=det.title)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("worker_error", error=str(exc))
            await asyncio.sleep(2)


def _parse_value(value: str):
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value


if __name__ == "__main__":
    asyncio.run(run_worker())
