"""Policy engine FastAPI service."""

import json
import time
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

from roscyber import __version__
from roscyber.ingestion.auth import Role, User, get_current_user, require_role
from roscyber.ingestion.schemas import CommandIn, CommandOut, HealthResponse
from roscyber.policy.engine import PolicyEngine
from roscyber.shared.config import get_settings
from roscyber.shared.database import get_db, init_db
from roscyber.shared.logging import configure_logging, get_correlation_id, get_logger, set_correlation_id
from roscyber.shared.metrics import BLOCKED_COMMANDS, KILL_SWITCH, REQUESTS_TOTAL, metrics_response
from roscyber.shared.models import AuditDecision, CommandAuditLog
from roscyber.shared.redis_client import publish_event

configure_logging()
logger = get_logger("policy")
engine = PolicyEngine()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="ROS Cyber Policy Engine", version=__version__)

    @app.on_event("startup")
    async def startup() -> None:
        await init_db()
        engine.reload()

    @app.middleware("http")
    async def add_correlation(request: Request, call_next):
        set_correlation_id(request.headers.get("X-Correlation-ID", get_correlation_id()))
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = get_correlation_id()
        return response

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(status="healthy", service="policy", version=__version__)

    @app.get("/ready", response_model=HealthResponse)
    async def ready() -> HealthResponse:
        return HealthResponse(status="ready", service="policy", version=__version__)

    @app.get("/metrics")
    async def metrics() -> Response:
        return PlainTextResponse(metrics_response(), media_type="text/plain")

    @app.post("/v1/commands/evaluate", response_model=CommandOut)
    async def evaluate_command(
        body: CommandIn,
        request: Request,
        db: Annotated[AsyncSession, Depends(get_db)],
        user: Annotated[User, Depends(get_current_user)],
    ) -> CommandOut:
        start = time.perf_counter()
        cmd_dict = body.model_dump()
        decision = engine.evaluate_command(cmd_dict)
        cid = get_correlation_id()

        audit = CommandAuditLog(
            robot_id=body.robot_id,
            user_id=user.username,
            command_type=body.command_type,
            payload=json.dumps(cmd_dict),
            decision=AuditDecision.ALLOW.value if decision.approved else AuditDecision.DENY.value,
            reason=decision.reason,
            correlation_id=cid,
        )
        db.add(audit)
        await db.commit()

        if not decision.approved:
            BLOCKED_COMMANDS.labels(robot_id=body.robot_id).inc()
            await publish_event(
                settings.detection_stream,
                {
                    "event_type": "policy_violation",
                    "robot_id": body.robot_id,
                    "rule": decision.rule_name,
                    "reason": decision.reason,
                    "user": user.username,
                },
            )

        if decision.approved:
            await publish_event(
                settings.detection_stream,
                {
                    "event_type": "command_approved",
                    "robot_id": body.robot_id,
                    "linear_x": body.linear_x,
                    "angular_z": body.angular_z,
                },
            )

        REQUESTS_TOTAL.labels(
            service="policy", method="POST", endpoint="/v1/commands/evaluate", status="200"
        ).inc()
        _ = time.perf_counter() - start

        return CommandOut(
            robot_id=body.robot_id,
            decision="allow" if decision.approved else "deny",
            reason=decision.reason,
            approved=decision.approved,
        )

    @app.post("/v1/kill-switch/{state}")
    async def kill_switch(
        state: str,
        user: Annotated[User, Depends(require_role(Role.ADMIN))],
    ) -> dict[str, bool]:
        active = state.lower() == "on"
        engine.set_kill_switch(active)
        KILL_SWITCH.set(1 if active else 0)
        await publish_event(
            settings.detection_stream,
            {"event_type": "kill_switch", "robot_id": "fleet", "active": active, "user": user.username},
        )
        return {"kill_switch_active": active}

    @app.post("/v1/policies/reload")
    async def reload_policies(user: Annotated[User, Depends(require_role(Role.ADMIN))]) -> dict[str, int]:
        engine.reload()
        return {"rules_loaded": len(engine.rules)}

    return app


app = create_app()
