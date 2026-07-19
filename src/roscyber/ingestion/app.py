"""FastAPI ingestion service."""

import time
from collections import defaultdict
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from roscyber import __version__
from roscyber.ingestion.auth import (
    USERS,
    Role,
    User,
    create_access_token,
    get_current_user,
    require_role,
    verify_password,
)
from roscyber.ingestion.schemas import (
    EventIn,
    HealthResponse,
    TelemetryIn,
    TelemetryOut,
    TokenRequest,
    TokenResponse,
)
from roscyber.shared.config import Settings, get_settings
from roscyber.shared.database import get_db, init_db
from roscyber.shared.logging import (
    configure_logging,
    get_correlation_id,
    get_logger,
    set_correlation_id,
)
from roscyber.shared.metrics import REQUEST_LATENCY, REQUESTS_TOTAL, metrics_response
from roscyber.shared.models import RobotTelemetry
from roscyber.shared.redis_client import publish_event

configure_logging()
logger = get_logger("ingestion")

_rate_buckets: dict[str, list[float]] = defaultdict(list)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(
        title="ROS Cyber Ingestion API",
        description="Telemetry and event ingestion for ROS2 robot fleets",
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def correlation_and_metrics(request: Request, call_next):
        cid = request.headers.get("X-Correlation-ID", get_correlation_id())
        set_correlation_id(cid)
        start = time.perf_counter()
        response = await call_next(request)
        elapsed = time.perf_counter() - start
        REQUEST_LATENCY.labels(service="ingestion", endpoint=request.url.path).observe(elapsed)
        REQUESTS_TOTAL.labels(
            service="ingestion",
            method=request.method,
            endpoint=request.url.path,
            status=str(response.status_code),
        ).inc()
        response.headers["X-Correlation-ID"] = cid
        return response

    @app.on_event("startup")
    async def startup() -> None:
        await init_db()
        logger.info("ingestion_started", profile=settings.profile)

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(status="healthy", service="ingestion", version=__version__)

    @app.get("/ready", response_model=HealthResponse)
    async def ready() -> HealthResponse:
        return HealthResponse(status="ready", service="ingestion", version=__version__)

    @app.get("/metrics")
    async def metrics() -> Response:
        return PlainTextResponse(metrics_response(), media_type="text/plain")

    def _check_rate_limit(client_ip: str) -> None:
        if settings.profile == "vulnerable":
            return
        now = time.time()
        bucket = _rate_buckets[client_ip]
        _rate_buckets[client_ip] = [t for t in bucket if now - t < 60]
        if len(_rate_buckets[client_ip]) >= settings.rate_limit_per_minute:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        _rate_buckets[client_ip].append(now)

    @app.post("/v1/auth/token", response_model=TokenResponse)
    async def login(body: TokenRequest, request: Request) -> TokenResponse:
        _check_rate_limit(request.client.host if request.client else "unknown")
        user = USERS.get(body.username)
        if not user or not verify_password(body.password, user["password_hash"]):
            await publish_event(
                settings.detection_stream,
                {
                    "event_type": "auth_failure",
                    "robot_id": "fleet",
                    "username": body.username,
                    "source_ip": request.client.host if request.client else "",
                },
            )
            raise HTTPException(status_code=401, detail="Invalid credentials")
        token = create_access_token(body.username, Role(user["role"]))
        await publish_event(
            settings.detection_stream,
            {"event_type": "auth_success", "robot_id": "fleet", "username": body.username},
        )
        return TokenResponse(access_token=token)

    @app.post("/v1/telemetry", response_model=TelemetryOut)
    async def ingest_telemetry(
        body: TelemetryIn,
        request: Request,
        db: Annotated[AsyncSession, Depends(get_db)],
        user: Annotated[object, Depends(get_current_user)],
    ) -> TelemetryOut:
        _check_rate_limit(request.client.host if request.client else "unknown")

        if settings.profile == "vulnerable":
            requested_id = request.query_params.get("robot_id")
            if requested_id:
                body.robot_id = requested_id

        record = RobotTelemetry(
            robot_id=body.robot_id,
            latitude=body.latitude,
            longitude=body.longitude,
            imu_x=body.imu_x,
            imu_y=body.imu_y,
            imu_z=body.imu_z,
            battery_pct=body.battery_pct,
            motor_rpm=body.motor_rpm,
            firmware_version=body.firmware_version,
        )
        db.add(record)
        await db.commit()
        await db.refresh(record)

        await publish_event(
            settings.detection_stream,
            {
                "event_type": "telemetry",
                "robot_id": body.robot_id,
                "latitude": body.latitude,
                "longitude": body.longitude,
                "motor_rpm": body.motor_rpm,
                "battery_pct": body.battery_pct,
            },
        )
        return TelemetryOut(
            id=record.id,
            robot_id=record.robot_id,
            latitude=record.latitude,
            longitude=record.longitude,
            imu_x=record.imu_x,
            imu_y=record.imu_y,
            imu_z=record.imu_z,
            battery_pct=record.battery_pct,
            motor_rpm=record.motor_rpm,
            firmware_version=record.firmware_version,
            recorded_at=record.recorded_at,
        )

    @app.get("/v1/robots/{robot_id}/telemetry", response_model=list[TelemetryOut])
    async def get_robot_telemetry(
        robot_id: str,
        db: Annotated[AsyncSession, Depends(get_db)],
        user: Annotated[User, Depends(get_current_user)],
    ) -> list[TelemetryOut]:
        if settings.profile == "hardened" and user.role == Role.OPERATOR:
            raise HTTPException(
                status_code=403,
                detail="Operators cannot read arbitrary robot telemetry",
            )

        query = (
            select(RobotTelemetry)
            .where(RobotTelemetry.robot_id == robot_id)
            .order_by(RobotTelemetry.id.desc())
            .limit(50)
        )
        result = await db.execute(query)
        rows = result.scalars().all()
        return [
            TelemetryOut(
                id=r.id,
                robot_id=r.robot_id,
                latitude=r.latitude,
                longitude=r.longitude,
                imu_x=r.imu_x,
                imu_y=r.imu_y,
                imu_z=r.imu_z,
                battery_pct=r.battery_pct,
                motor_rpm=r.motor_rpm,
                firmware_version=r.firmware_version,
                recorded_at=r.recorded_at,
            )
            for r in rows
        ]

    @app.post("/v1/events")
    async def ingest_event(
        body: EventIn,
        user: Annotated[object, Depends(get_current_user)],
    ) -> dict[str, str]:
        await publish_event(
            settings.detection_stream,
            {"event_type": body.event_type, "robot_id": body.robot_id, **body.payload},
        )
        return {"status": "queued"}

    @app.get("/v1/admin/config")
    async def admin_config(
        user: Annotated[object, Depends(require_role(Role.ADMIN))],
    ) -> dict[str, str]:
        if settings.profile == "hardened":
            raise HTTPException(status_code=403, detail="Admin config disabled in hardened mode")
        return {"jwt_secret": settings.jwt_secret, "profile": settings.profile}

    return app


app = create_app()
