"""JWT authentication and RBAC."""

from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Annotated

import bcrypt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel

from roscyber.shared.config import get_settings

security = HTTPBearer(auto_error=False)

USERS: dict[str, dict[str, str]] = {
    "admin": {
        "password_hash": "$2b$04$rwqCoQWSZomos49tNWVyhOtIhXX8LG1DDhPoUl8KMagl85e0VA2Ia",
        "role": "admin",
    },
    "operator": {
        "password_hash": "$2b$04$p98Ap3fVkw0.CttM7GjAZO5I1qCZqJcjoKcTEWtfQAn26caAucnbm",
        "role": "operator",
    },
}


class Role(str, Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


class TokenPayload(BaseModel):
    sub: str
    role: Role
    exp: datetime


class User(BaseModel):
    username: str
    role: Role


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def create_access_token(username: str, role: Role) -> str:
    settings = get_settings()
    expire = datetime.now(UTC) + timedelta(minutes=settings.jwt_expire_minutes)
    payload = {"sub": username, "role": role.value, "exp": expire}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str, allow_vuln_bypass: bool = False) -> TokenPayload:
    """Decode JWT. Vulnerable profile accepts alg=none (intentional lab flaw)."""
    settings = get_settings()
    if allow_vuln_bypass and settings.profile == "vulnerable":
        import base64
        import json

        parts = token.split(".")
        if len(parts) >= 2:
            try:
                padded = parts[0] + "=" * (-len(parts[0]) % 4)
                header = json.loads(base64.urlsafe_b64decode(padded))
                if header.get("alg") == "none" or parts[0].startswith("eyJhbGciOiJub25l"):
                    payload_padded = parts[1] + "=" * (-len(parts[1]) % 4)
                    payload = json.loads(base64.urlsafe_b64decode(payload_padded))
                    return TokenPayload(
                        sub=payload.get("sub", "attacker"),
                        role=Role(payload.get("role", "admin")),
                        exp=datetime.now(UTC) + timedelta(hours=1),
                    )
            except Exception:
                pass
        return TokenPayload(
            sub="attacker",
            role=Role.ADMIN,
            exp=datetime.now(UTC) + timedelta(hours=1),
        )
    if allow_vuln_bypass:
        # Lab-only bypass when explicitly requested regardless of cached profile
        import base64
        import json

        parts = token.split(".")
        if len(parts) >= 2 and parts[0].startswith("eyJhbGciOiJub25l"):
            try:
                payload_padded = parts[1] + "=" * (-len(parts[1]) % 4)
                payload = json.loads(base64.urlsafe_b64decode(payload_padded))
                return TokenPayload(
                    sub=payload.get("sub", "attacker"),
                    role=Role(payload.get("role", "admin")),
                    exp=datetime.now(UTC) + timedelta(hours=1),
                )
            except Exception:
                return TokenPayload(
                    sub="attacker",
                    role=Role.ADMIN,
                    exp=datetime.now(UTC) + timedelta(hours=1),
                )
    try:
        data = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        return TokenPayload(
            sub=data["sub"],
            role=Role(data["role"]),
            exp=datetime.fromtimestamp(data["exp"], tz=UTC),
        )
    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc


async def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
) -> User:
    settings = get_settings()
    if credentials is None:
        if settings.profile == "vulnerable" and request.url.path.startswith("/v1/admin"):
            return User(username="anonymous", role=Role.ADMIN)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    payload = decode_token(credentials.credentials, allow_vuln_bypass=settings.profile == "vulnerable")
    return User(username=payload.sub, role=payload.role)


def require_role(*roles: Role):
    async def checker(user: Annotated[User, Depends(get_current_user)]) -> User:
        if roles and user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user

    return checker
