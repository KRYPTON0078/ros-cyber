"""Application configuration via Pydantic Settings."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "ROS Cyber"
    environment: str = Field(default="development", alias="ENVIRONMENT")
    debug: bool = False
    profile: str = Field(default="hardened", alias="ROSCYBER_PROFILE")

    database_url: str = Field(
        default="postgresql+asyncpg://roscyber:roscyber@localhost:5432/roscyber",
        alias="DATABASE_URL",
    )
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")
    mqtt_host: str = Field(default="localhost", alias="MQTT_HOST")
    mqtt_port: int = Field(default=1883, alias="MQTT_PORT")

    jwt_secret: str = Field(default="change-me-in-production-use-long-random-string", alias="JWT_SECRET")
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    ingestion_host: str = "0.0.0.0"
    ingestion_port: int = 8000
    policy_port: int = 8001
    dashboard_port: int = 8002
    detection_stream: str = "roscyber:events"
    alert_stream: str = "roscyber:alerts"

    rate_limit_per_minute: int = 120
    telemetry_flood_threshold: int = 50
    gps_jump_threshold_m: float = 500.0

    policies_dir: str = "policies"
    kill_switch_active: bool = False

    cors_origins: list[str] = Field(default_factory=lambda: ["*"])


@lru_cache
def get_settings() -> Settings:
    return Settings()
