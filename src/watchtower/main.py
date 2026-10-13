"""Watchtower API: authentication, workspace access control, audit logs, and events."""

import hashlib
import logging
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, inspect, select, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from watchtower.database import Base, engine, get_db
from watchtower.models import (
    AuditLog,
    SecurityEvent,
    User,
    Workspace,
    WorkspaceInvitation,
    WorkspaceMembership,
)
from watchtower.schemas import (
    AuditLogRead,
    AuthResponse,
    EventList,
    InvitationAccept,
    InvitationCreate,
    InvitationCreated,
    InvitationRead,
    LoginRequest,
    MembershipRoleUpdate,
    RegisterRequest,
    SecurityEventCreate,
    SecurityEventRead,
    UserRead,
    WorkspaceRead,
)
from watchtower.threat_intel import (\n    IPReputation,\n    ThreatIntelConfigurationError,\n    ThreatIntelRateLimited,\n    ThreatIntelUnavailable,\n    lookup_ip_reputation,\n)\nfrom watchtower.security import (
    ACCESS_TOKEN_MINUTES,
    create_access_token,
    get_current_user,
    hash_password,
    validate_security_config,
    verify_password,
)

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
logger = logging.getLogger("watchtower")
ALLOWED_ROLES = {"owner", "admin", "analyst", "viewer"}
MANAGEMENT_ROLES = {"owner", "admin"}
WRITE_ROLES = {"owner", "admin", "analyst"}


def initialize_database() -> None:
    """Create current tables and add workspace_id to legacy event tables."""
    validate_security_config()
    Base.metadata.create_all(bind=engine)
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
    description="Workspace-isolated security telemetry, accounts, and access control.",
    version="0.3.0",
    lifespan=lifespan,
)


_cors_origins = [
    origin.strip()
    for origin in os.getenv(
        "WATCHTOWER_CORS_ORIGINS",
        "https://btwsalts.github.io,http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Workspace-ID"],
)


@app.get("/healthz", tags=["system"])
def health_check() -> dict[str, str]:
    return {"status": "ok", "service": "watchtower-api"}


@app.get("/readyz", tags=["system"])
def readiness_check(db: Annotated[Session, Depends(get_db)]) -> dict[str, str]:
    try:
        db.execute(select(1))
    except SQLAlchemyError as exc:
        logger.exception("Database readiness check failed")
        raise HTTPException(status_code=503, detail="database unavailable") from exc
    return {"status": "ready", "database": "ok"}


def audit(
    db: Session,
    action: str,
    *,
    actor_user_id: str | None = None,
    workspace_id: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    details: dict | None = None,
) -> None:
    """Append a small, structured audit record in the caller's transaction."""
    db.add(AuditLog(
        actor_user_id=actor_user_id,
        workspace_id=workspace_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=details or {},
    ))


def build_auth_response(db: Session, user: User, membership: WorkspaceMembership) -> AuthResponse:
    workspace = db.get(Workspace, membership.workspace_id)
    if workspace is None:
        raise HTTPException(status_code=500, detail="Workspace membership is invalid")
    return AuthResponse(
        access_token=create_access_token(user.id),
        expires_in=ACCESS_TOKEN_MINUTES * 60,
        user=UserRead.model_validate(user),
        workspace=WorkspaceRead(
            id=workspace.id, name=workspace.name, role=membership.role, created_at=workspace.created_at
        ),
    )


@app.post("/api/v1/auth/register", response_model=AuthResponse, status_code=201, tags=["authentication"])
def register(payload: RegisterRequest, db: Annotated[Session, Depends(get_db)]) -> AuthResponse:
    if db.scalar(select(User.id).where(User.email == payload.email)):
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    user = User(email=payload.email, display_name=payload.display_name, password_hash=hash_password(payload.password))
    workspace = Workspace(name=payload.workspace_name)
    db.add_all([user, workspace])
    try:
        db.flush()
        membership = WorkspaceMembership(user_id=user.id, workspace_id=workspace.id, role="owner")
        db.add(membership)
        audit(db, "account.registered", actor_user_id=user.id, workspace_id=workspace.id,
              target_type="user", target_id=user.id)
        db.commit()
        db.refresh(user)
        db.refresh(workspace)
        db.refresh(membership)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Account could not be created with these details") from exc
    return build_auth_response(db, user, membership)


@app.post("/api/v1/auth/login", response_model=AuthResponse, tags=["authentication"])
def login(payload: LoginRequest, db: Annotated[Session, Depends(get_db)]) -> AuthResponse:
    user = db.scalar(select(User).where(User.email == payload.email))
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password",
                            headers={"WWW-Authenticate": "Bearer"})
    membership = db.scalar(
        select(WorkspaceMembership).where(WorkspaceMembership.user_id == user.id)
        .order_by(WorkspaceMembership.created_at.asc())
    )
    if membership is None:
        raise HTTPException(status_code=403, detail="Account has no workspace membership")
    audit(db, "auth.login_succeeded", actor_user_id=user.id, workspace_id=membership.workspace_id,
          target_type="user", target_id=user.id)
    db.commit()
    return build_auth_response(db, user, membership)


@app.get("/api/v1/auth/me", response_model=UserRead, tags=["authentication"])
def get_me(user: Annotated[User, Depends(get_current_user)]) -> User:
    return user


def require_workspace(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    workspace_id: Annotated[str, Header(alias="X-Workspace-ID")],
) -> WorkspaceMembership:
    membership = db.scalar(select(WorkspaceMembership).where(
        WorkspaceMembership.user_id == user.id,
        WorkspaceMembership.workspace_id == workspace_id,
    ))
    if membership is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return membership


def require_management_role(membership: WorkspaceMembership) -> None:
    if membership.role not in MANAGEMENT_ROLES:
        raise HTTPException(status_code=403, detail="Workspace owner or admin role required")


@app.get("/api/v1/workspaces", response_model=list[WorkspaceRead], tags=["workspaces"])
def list_workspaces(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> list[WorkspaceRead]:
    rows = db.execute(
        select(Workspace, WorkspaceMembership.role)
        .join(WorkspaceMembership, WorkspaceMembership.workspace_id == Workspace.id)
        .where(WorkspaceMembership.user_id == user.id)
        .order_by(Workspace.created_at.asc())
    ).all()
    return [WorkspaceRead(id=w.id, name=w.name, role=role, created_at=w.created_at) for w, role in rows]


@app.post("/api/v1/workspaces/invitations", response_model=InvitationCreated, status_code=201, tags=["workspaces"])
def create_invitation(
    payload: InvitationCreate,
    membership: Annotated[WorkspaceMembership, Depends(require_workspace)],
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> InvitationCreated:
    require_management_role(membership)
    if payload.role not in {"admin", "analyst", "viewer"}:
        raise HTTPException(status_code=422, detail="This role cannot be assigned through an invitation")
    existing_user = db.scalar(select(User).where(User.email == payload.email))
    if existing_user and db.scalar(select(WorkspaceMembership.id).where(
        WorkspaceMembership.user_id == existing_user.id,
        WorkspaceMembership.workspace_id == membership.workspace_id,
    )):
        raise HTTPException(status_code=409, detail="This user is already a workspace member")

    raw_token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    invitation = WorkspaceInvitation(
        workspace_id=membership.workspace_id,
        email=payload.email,
        role=payload.role,
        token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
        invited_by_user_id=user.id,
        expires_at=expires_at,
    )
    db.add(invitation)
    db.flush()
    audit(db, "workspace.invitation_created", actor_user_id=user.id, workspace_id=membership.workspace_id,
          target_type="invitation", target_id=invitation.id, details={"email": payload.email, "role": payload.role})
    db.commit()
    db.refresh(invitation)
    return InvitationCreated(
        id=invitation.id, email=invitation.email, role=invitation.role, expires_at=invitation.expires_at,
        created_at=invitation.created_at, invite_token=raw_token,
    )


@app.get("/api/v1/workspaces/invitations", response_model=list[InvitationRead], tags=["workspaces"])
def list_invitations(
    membership: Annotated[WorkspaceMembership, Depends(require_workspace)],
    db: Annotated[Session, Depends(get_db)],
) -> list[InvitationRead]:
    require_management_role(membership)
    now = datetime.now(timezone.utc)
    rows = db.scalars(select(WorkspaceInvitation).where(
        WorkspaceInvitation.workspace_id == membership.workspace_id,
        WorkspaceInvitation.accepted_at.is_(None),
        WorkspaceInvitation.expires_at > now,
    ).order_by(WorkspaceInvitation.created_at.desc())).all()
    return [InvitationRead(id=i.id, email=i.email, role=i.role, expires_at=i.expires_at, created_at=i.created_at) for i in rows]


@app.post("/api/v1/workspaces/invitations/accept", response_model=WorkspaceRead, tags=["workspaces"])
def accept_invitation(
    payload: InvitationAccept,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> WorkspaceRead:
    token_hash = hashlib.sha256(payload.invite_token.encode()).hexdigest()
    now = datetime.now(timezone.utc)
    invitation = db.scalar(select(WorkspaceInvitation).where(
        WorkspaceInvitation.token_hash == token_hash,
        WorkspaceInvitation.accepted_at.is_(None),
        WorkspaceInvitation.expires_at > now,
    ))
    if invitation is None:
        raise HTTPException(status_code=400, detail="Invitation is invalid, expired, or already used")
    if invitation.email != user.email:
        raise HTTPException(status_code=403, detail="Sign in with the email address this invitation was sent to")
    if db.scalar(select(WorkspaceMembership.id).where(
        WorkspaceMembership.user_id == user.id,
        WorkspaceMembership.workspace_id == invitation.workspace_id,
    )):
        raise HTTPException(status_code=409, detail="You are already a workspace member")

    invitation.accepted_at = now
    membership = WorkspaceMembership(user_id=user.id, workspace_id=invitation.workspace_id, role=invitation.role)
    db.add(membership)
    db.flush()
    audit(db, "workspace.invitation_accepted", actor_user_id=user.id, workspace_id=invitation.workspace_id,
          target_type="membership", target_id=membership.id, details={"role": invitation.role})
    db.commit()
    workspace = db.get(Workspace, invitation.workspace_id)
    return WorkspaceRead(id=workspace.id, name=workspace.name, role=membership.role, created_at=workspace.created_at)


@app.get("/api/v1/workspaces/members", tags=["workspaces"])
def list_members(
    membership: Annotated[WorkspaceMembership, Depends(require_workspace)],
    db: Annotated[Session, Depends(get_db)],
) -> list[dict]:
    require_management_role(membership)
    rows = db.execute(
        select(WorkspaceMembership, User.email, User.display_name)
        .join(User, User.id == WorkspaceMembership.user_id)
        .where(WorkspaceMembership.workspace_id == membership.workspace_id)
        .order_by(WorkspaceMembership.created_at.asc())
    ).all()
    return [{"membership_id": m.id, "user_id": m.user_id, "email": email, "display_name": name,
             "role": m.role, "created_at": m.created_at} for m, email, name in rows]


@app.patch("/api/v1/workspaces/members/{membership_id}", tags=["workspaces"])
def update_member_role(
    membership_id: str,
    payload: MembershipRoleUpdate,
    actor_membership: Annotated[WorkspaceMembership, Depends(require_workspace)],
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> dict:
    require_management_role(actor_membership)
    target = db.scalar(select(WorkspaceMembership).where(
        WorkspaceMembership.id == membership_id,
        WorkspaceMembership.workspace_id == actor_membership.workspace_id,
    ))
    if target is None:
        raise HTTPException(status_code=404, detail="Workspace member not found")
    if target.role == "owner" or payload.role == "owner":
        raise HTTPException(status_code=403, detail="Owner role changes are not available through this endpoint")
    previous_role = target.role
    target.role = payload.role
    audit(db, "workspace.member_role_changed", actor_user_id=user.id, workspace_id=actor_membership.workspace_id,
          target_type="membership", target_id=target.id, details={"from": previous_role, "to": payload.role})
    db.commit()
    return {"membership_id": target.id, "user_id": target.user_id, "role": target.role}


@app.get("/api/v1/audit-logs", response_model=list[AuditLogRead], tags=["audit"])
def list_audit_logs(
    membership: Annotated[WorkspaceMembership, Depends(require_workspace)],
    db: Annotated[Session, Depends(get_db)],
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> list[AuditLogRead]:
    require_management_role(membership)
    rows = db.scalars(select(AuditLog).where(AuditLog.workspace_id == membership.workspace_id)
                      .order_by(AuditLog.created_at.desc()).offset(offset).limit(limit)).all()
    return [AuditLogRead.model_validate(row) for row in rows]


@app.post("/api/v1/events", response_model=SecurityEventRead, status_code=201, tags=["events"])
def ingest_event(
    payload: SecurityEventCreate,
    membership: Annotated[WorkspaceMembership, Depends(require_workspace)],
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> SecurityEvent:
    if membership.role not in WRITE_ROLES:
        raise HTTPException(status_code=403, detail="Viewer role cannot ingest events")
    event = SecurityEvent(
        workspace_id=membership.workspace_id, timestamp=payload.normalized_timestamp(),
        event_type=payload.event_type, source=payload.source,
        hostname=payload.hostname.strip() if payload.hostname else None, source_ip=payload.source_ip,
        username=payload.username, severity=payload.severity, message=payload.message, raw_event=payload.raw_event,
    )
    db.add(event)
    try:
        db.flush()
        audit(db, "event.ingested", actor_user_id=user.id, workspace_id=membership.workspace_id,
              target_type="security_event", target_id=event.id, details={"severity": event.severity, "event_type": event.event_type})
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
        events = db.execute(statement.order_by(SecurityEvent.timestamp.desc(), SecurityEvent.received_at.desc())
                            .offset(offset).limit(limit)).scalars().all()
    except SQLAlchemyError as exc:
        logger.exception("Failed to query security events")
        raise HTTPException(status_code=500, detail="events could not be retrieved") from exc
    return EventList(items=events, limit=limit, offset=offset, count=total)



@app.get(
    "/api/v1/threat-intel/ip/{ip_address}",
    response_model=IPReputation,
    tags=["threat intelligence"],
)
async def check_ip_reputation(
    ip_address: str,
    membership: Annotated[WorkspaceMembership, Depends(require_workspace)],
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> IPReputation:
    """Enrich a public IP with AbuseIPDB reputation for an authenticated workspace member."""
    try:
        result = await lookup_ip_reputation(ip_address)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ThreatIntelConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ThreatIntelRateLimited as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except ThreatIntelUnavailable as exc:
        logger.warning("Threat-intelligence lookup unavailable: %s", exc)
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    audit(
        db,
        "threat_intel.ip_lookup",
        actor_user_id=user.id,
        workspace_id=membership.workspace_id,
        target_type="ip_address",
        target_id=result.ip_address,
        details={
            "provider": result.provider,
            "abuse_confidence_score": result.abuse_confidence_score,
            "cached": result.cached,
        },
    )
    db.commit()
    return result
