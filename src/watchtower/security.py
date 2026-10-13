"""Password hashing and signed access-token helpers."""

import os
from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash
from sqlalchemy import select
from sqlalchemy.orm import Session

from watchtower.database import get_db
from watchtower.models import User

ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = 60
# Development-only fallback. Production must supply a secret through the environment.
_DEVELOPMENT_SECRET = "watchtower-local-development-secret-change-before-production"
password_hash = PasswordHash.recommended()
_bearer = HTTPBearer(auto_error=False)


def get_jwt_secret() -> str:
    return os.getenv("WATCHTOWER_JWT_SECRET", _DEVELOPMENT_SECRET)


def validate_security_config() -> None:
    """Fail startup if production is configured with the development signing secret."""
    app_env = os.getenv("APP_ENV", "development").strip().lower()
    secret = os.getenv("WATCHTOWER_JWT_SECRET", "").strip()
    if app_env in {"production", "prod"} and len(secret) < 32:
        raise RuntimeError(
            "Production requires WATCHTOWER_JWT_SECRET with at least 32 random characters."
        )


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        return password_hash.verify(password, stored_hash)
    except Exception:
        return False


def create_access_token(user_id: str) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": user_id,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_MINUTES),
        "iss": "watchtower",
    }
    return jwt.encode(claims, get_jwt_secret(), algorithm=ALGORITHM)


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """Validate a signed bearer token and return its active account."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer access token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        claims = jwt.decode(
            credentials.credentials,
            get_jwt_secret(),
            algorithms=[ALGORITHM],
            issuer="watchtower",
            options={"require": ["sub", "exp", "iat", "iss"]},
        )
        user_id = claims.get("sub")
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user = db.scalar(select(User).where(User.id == user_id, User.is_active.is_(True)))
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account is unavailable")
    return user
