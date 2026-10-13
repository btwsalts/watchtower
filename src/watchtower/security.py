"""Shared bearer-token protection for early API deployments.

This is a transitional service credential, not user authentication or tenant isolation.
"""
import hmac
import os
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer = HTTPBearer(auto_error=False)


def validate_security_config() -> None:
    """Fail startup rather than run an unprotected production API."""
    app_env = os.getenv("APP_ENV", "development").strip().lower()
    token = os.getenv("WATCHTOWER_API_TOKEN", "").strip()
    if app_env in {"production", "prod"} and len(token) < 32:
        raise RuntimeError(
            "Production requires WATCHTOWER_API_TOKEN with at least 32 characters. "
            "Use a secrets manager and rotate the token if it is exposed."
        )


def require_api_token(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> None:
    """Require a constant-time compared bearer token when configured."""
    token = os.getenv("WATCHTOWER_API_TOKEN", "").strip()
    app_env = os.getenv("APP_ENV", "development").strip().lower()

    if not token and app_env not in {"production", "prod"}:
        # Convenient for local development only. Production startup fails closed.
        return

    if not token or len(token) < 32:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication is not configured",
        )

    supplied = credentials.credentials if credentials else ""
    if not hmac.compare_digest(supplied, token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A valid bearer token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )
