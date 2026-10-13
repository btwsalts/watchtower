"""Pydantic request and response schemas."""

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Severity = Literal["info", "low", "medium", "high", "critical"]


class SecurityEventCreate(BaseModel):
    """Incoming event fields accepted by the ingestion API."""

    timestamp: datetime | None = None
    event_type: str = Field(min_length=1, max_length=100)
    source: str = Field(default="unknown", min_length=1, max_length=100)
    hostname: str | None = Field(default=None, max_length=255)
    source_ip: str | None = Field(default=None, max_length=45)
    username: str | None = Field(default=None, max_length=255)
    severity: Severity = "info"
    message: str = Field(min_length=1, max_length=10000)
    raw_event: dict = Field(default_factory=dict)

    @field_validator("event_type")
    @classmethod
    def normalize_event_type(cls, value: str) -> str:
        normalized = "_".join(value.strip().lower().replace("-", " ").split())
        if not normalized:
            raise ValueError("event_type must contain a non-whitespace character")
        return normalized

    @field_validator("source")
    @classmethod
    def normalize_source(cls, value: str) -> str:
        value = value.strip().lower()
        if not value:
            raise ValueError("source must contain a non-whitespace character")
        return value

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, value: str) -> str:
        return value.strip().lower() if isinstance(value, str) else value

    def normalized_timestamp(self) -> datetime:
        """Return the supplied timestamp in UTC, or the current UTC time."""
        value = self.timestamp or datetime.now(timezone.utc)
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class SecurityEventRead(BaseModel):
    """Event representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    timestamp: datetime
    received_at: datetime
    event_type: str
    source: str
    hostname: str | None
    source_ip: str | None
    username: str | None
    severity: Severity
    message: str
    raw_event: dict


class EventList(BaseModel):
    items: list[SecurityEventRead]
    limit: int
    offset: int
    count: int
