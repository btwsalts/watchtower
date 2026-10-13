"""Watchtower API: account registration, workspace isolation, and event ingestion."""

import logging
import os
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from sqlalchemy import func, inspect, select, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from watchtower.database import Base, engine, get_db
from watchtower.models import SecurityEvent, User, Workspace, WorkspaceMembership
from watchtower.schemas import (
    AuthResponse,
    EventList,
    LoginRequest,
    RegisterRequest,
    SecurityEventCreate,
    SecurityEventRead,
    UserRead,
    WorkspaceRead,
)
from watchtower.security import (
    ACCESS_TOKEN_MINUTES,
    create_access_token,
    get_current_user,
    hash_password,
    validate_security_config,
    verify_password,
)

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
logger = logging.getLogger("watchtower")


def initialize_database() -> None:
    """Create current tables and add the workspace column to older event databases."""
    validate_security_config()
    Base.metadata.create_all(bind=engine)

    # create_all does not alter an existing table. Preserve legacy rows as unassigned;
    # all API-created events are assigned to a verified workspace and legacy rows are never listed.
    columns = {column["name"] for column in inspect(engine).get_columns("security_events")}
    if "workspace_id" not in columns:
        with engine.begin() as connection:
            connection.execute(
                text("ALTER TABLE security_events ADD COLUMN workspace_id VARCHAR(36) REFERENCES workspaces(id)")
            )

    for index in SecurityEvent.__table__.indexes:
        index.create(bind=engine, checkfirst=True)


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    logger.info("Watchtower database initialized")
    yield


app = FastAPI(
    title="Watchtower API",
    description="Workspace-isolated security telemetry and account APIs for Watchtower.",
    version="0.2.0",
    lifespan=lifespan,
)


@app.get("/healthz", tags=["system"])
def health_check() -> dict[str, str]:
    """Lightweight process health endpoint; database readiness is separate."""
    return {"status": "ok", "service": "watchtower-api"}


@app.get("/readyz", tags=["system"])
def readiness_check(db: Annotated[Session, Depends(get_db)]) -> dict[str, str]:
    """Report ready only when the database can be queried."""
    try:
        db.execute(select(1))
    except SQLAlchemyError as exc:
        logger.exception("Database readiness check failed")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="database unavailable") from exc
    return {"status": "ready", "database": "ok"}


def build_auth_response(db: Session, user: User, membership: WorkspaceMembership) -> AuthResponse:
    workspace = db.get(Workspace, membership.workspace_id)
    if workspace is None:
        raise HTTPException(status_code=500, detail="Workspace membership is invalid")
    return AuthResponse(
        access_token=create_access_token(user.id),
        expires_in=ACCESS_TOKEN_MINUTES * 60,
        user=UserRead.model_validate(user),
        workspace=WorkspaceRead(
            id=workspace.id,
            name=workspace.name,
            role=membership.role,
            created_at=workspace.created_at,
        ),
    )


@app.post("/api/v1/auth/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED, tags=["authentication"])
def register(payload: RegisterRequest, db: Annotated[Session, Depends(get_db)]) -> AuthResponse:
    """Create a user and their first private workspace; the user becomes its owner."""
    if db.scalar(select(User.id).where(User.email == payload.email)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account with this email already exists")

    user = User(
        email=payload.email,
        display_name=payload.display_name,
        password_hash=hash_password(payload.password),
    )
    workspace = Workspace(name=payload.workspace_name)
    db.add_all([user, workspace])
    try:
        db.flush()
        membership = WorkspaceMembership(user_id=user.id, workspace_id=workspace.id, role="owner")
        db.add(membership)
        db.commit()
        db.refresh(user)
        db.refresh(workspace)
        db.refresh(membership)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Account could not be created with these details") from exc
    return build_auth_response(db, user, membership)


@app.post("/api/v1/auth/login", response_model=AuthResponse, tags=["authentication"])
def login(payload: LoginRequest, db: Annotated[Session, Depends(get_db)]) -> AuthResponse:
    """Authenticate an account and return its first workspace context."""
    user = db.scalar(select(User).where(User.email == payload.email))
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    membership = db.scalar(
        select(WorkspaceMembership)
        .where(WorkspaceMembership.user_id == user.id)
        .order_by(WorkspaceMembership.created_at.asc())
    )
    if membership is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account has no workspace membership")
    return build_auth_response(db, user, membership)


@app.get("/api/v1/auth/me", response_model=UserRead, tags=["authentication"])
def get_me(user: Annotated[User, Depends(get_current_user)]) -> User:
    """Return the current authenticated account."""
    return user


@app.get("/api/v1/workspaces", response_model=list[WorkspaceRead], tags=["workspaces"])
def list_workspaces(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> list[WorkspaceRead]:
    """List only workspaces where the authenticated account is a member."""
    rows = db.execute(
        select(Workspace, WorkspaceMembership.role)
        .join(WorkspaceMembership, WorkspaceMembership.workspace_id == Workspace.id)
        .where(WorkspaceMembership.user_id == user.id)
        .order_by(Workspace.created_at.asc())
    ).all()
    return [
        WorkspaceRead(id=workspace.id, name=workspace.name, role=role, created_at=workspace.created_at)
        for workspace, role in rows
    ]


def require_workspace(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    workspace_id: Annotated[str, Header(alias="X-Workspace-ID")],
) -> WorkspaceMembership:
    """Resolve the requested workspace only if this user is a member."""
    membership = db.scalar(
        select(WorkspaceMembership).where(
            WorkspaceMembership.user_id == user.id,
            WorkspaceMembership.workspace_id == workspace_id,
        )
    )
    if membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found")
    return membership


@app.post(
    "/api/v1/events",
    response_model=SecurityEventRead,
    status_code=status.HTTP_201_CREATED,
    tags=["events"],
)
def ingest_event(
    payload: SecurityEventCreate,
    membership: Annotated[WorkspaceMembership, Depends(require_workspace)],
    db: Annotated[Session, Depends(get_db)],
) -> SecurityEvent:
    """Validate and persist an event in the caller's authorized workspace."""
    event = SecurityEvent(
        workspace_id=membership.workspace_id,
        timestamp=payload.normalized_timestamp(),
        event_type=payload.event_type,
        source=payload.source,
        hostname=payload.hostname.strip() if payload.hostname else None,
        source_ip=payload.source_ip,
        username=payload.username,
        severity=payload.severity,
        message=payload.message,
        raw_event=payload.raw_event,
    )
    db.add(event)
    try:
        db.commit()
        db.refresh(event)
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("Failed to persist incoming security event")
        raise HTTPException(status_code=500, detail="event could not be stored") from exc
    return event


@app.get("/api/v1/events", response_model=EventList, tags=["events"])
def list_events(
    membership: Annotated[WorkspaceMembership, Depends(require_workspace)],
    db: Annotated[Session, Depends(get_db)],
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    event_type: str | None = Query(default=None, max_length=100),
    severity: str | None = Query(default=None, pattern="^(info|low|medium|high|critical)$"),
    source_ip: str | None = Query(default=None, max_length=45),
) -> EventList:
    """Return only events in the selected authorized workspace."""
    statement = select(SecurityEvent).where(SecurityEvent.workspace_id == membership.workspace_id)
    if event_type:
        normalized_type = "_".join(event_type.strip().lower().replace("-", " ").split())
        statement = statement.where(SecurityEvent.event_type == normalized_type)
    if severity:
        statement = statement.where(SecurityEvent.severity == severity)
    if source_ip:
        statement = statement.where(SecurityEvent.source_ip == source_ip)

    try:
        total = db.scalar(select(func.count()).select_from(statement.subquery())) or 0
        events = db.execute(
            statement.order_by(SecurityEvent.timestamp.desc(), SecurityEvent.received_at.desc())
            .offset(offset)
            .limit(limit)
        ).scalars().all()
    except SQLAlchemyError as exc:
        logger.exception("Failed to query security events")
        raise HTTPException(status_code=500, detail="events could not be retrieved") from exc
    return EventList(items=events, limit=limit, offset=offset, count=total)
