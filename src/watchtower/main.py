"""Watchtower API application."""

import logging
import os
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from watchtower.database import Base, engine, get_db
from watchtower.models import SecurityEvent
from watchtower.schemas import EventList, SecurityEventCreate, SecurityEventRead
from watchtower.security import require_api_token, validate_security_config

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
logger = logging.getLogger("watchtower")


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Initialize database tables for this development milestone."""
    validate_security_config()
    Base.metadata.create_all(bind=engine)
    logger.info("Watchtower database initialized")
    yield


app = FastAPI(
    title="Watchtower API",
    description="Security event ingestion and retrieval for the Watchtower SOC platform.",
    version="0.1.0",
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


@app.post("/api/v1/events", response_model=SecurityEventRead, status_code=status.HTTP_201_CREATED, tags=["events"], dependencies=[Depends(require_api_token)])
def ingest_event(payload: SecurityEventCreate, db: Annotated[Session, Depends(get_db)]) -> SecurityEvent:
    """Validate, normalize, and persist one security event."""
    event = SecurityEvent(
        timestamp=payload.normalized_timestamp(),
        event_type=payload.event_type,
        source=payload.source,
        hostname=payload.hostname.strip() if payload.hostname else None,
        source_ip=payload.source_ip,
        username=payload.username,
        severity=payload.severity,
        message=payload.message.strip(),
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


@app.get("/api/v1/events", response_model=EventList, tags=["events"], dependencies=[Depends(require_api_token)])
def list_events(
    db: Annotated[Session, Depends(get_db)],
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    event_type: str | None = Query(default=None, max_length=100),
    severity: str | None = Query(default=None, pattern="^(info|low|medium|high|critical)$"),
    source_ip: str | None = Query(default=None, max_length=45),
) -> EventList:
    """Return newest events first, with simple filters and bounded pagination."""
    statement = select(SecurityEvent)
    if event_type:
        normalized_type = "_".join(event_type.strip().lower().replace("-", " ").split())
        statement = statement.where(SecurityEvent.event_type == normalized_type)
    if severity:
        statement = statement.where(SecurityEvent.severity == severity)
    if source_ip:
        statement = statement.where(SecurityEvent.source_ip == source_ip)

    try:
        total = db.scalar(select(func.count()).select_from(statement.subquery())) or 0
        events = db.execute(statement.order_by(SecurityEvent.timestamp.desc(), SecurityEvent.received_at.desc()).offset(offset).limit(limit)).scalars().all()
    except SQLAlchemyError as exc:
        logger.exception("Failed to query security events")
        raise HTTPException(status_code=500, detail="events could not be retrieved") from exc
    return EventList(items=events, limit=limit, offset=offset, count=total)
