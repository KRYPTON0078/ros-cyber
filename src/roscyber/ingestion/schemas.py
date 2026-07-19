"""Pydantic schemas for ingestion API."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class TokenRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TelemetryIn(BaseModel):
    robot_id: str = Field(..., min_length=1, max_length=64)
    latitude: float = Field(..., ge=-90, le=90)
    longitude: float = Field(..., ge=-180, le=180)
    imu_x: float = 0.0
    imu_y: float = 0.0
    imu_z: float = 0.0
    battery_pct: float = Field(default=100.0, ge=0, le=100)
    motor_rpm: float = 0.0
    firmware_version: str = "1.0.0"


class TelemetryOut(TelemetryIn):
    id: int
    recorded_at: datetime


class CommandIn(BaseModel):
    robot_id: str
    command_type: str = "cmd_vel"
    linear_x: float = 0.0
    linear_y: float = 0.0
    angular_z: float = 0.0
    params: dict[str, Any] = Field(default_factory=dict)


class CommandOut(BaseModel):
    robot_id: str
    decision: str
    reason: str
    approved: bool


class EventIn(BaseModel):
    event_type: str
    robot_id: str = "fleet"
    payload: dict[str, Any] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
