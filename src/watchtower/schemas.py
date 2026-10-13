"""Pydantic request and response schemas."""

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Severity = Literal["info", "low", "medium", "high", "critical"]
WorkspaceRole = Literal["owner", "admin", "analyst", "viewer"]


class RegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    display_name: str = Field(min_length=1, max_length=120)
    workspace_name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=12, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        value = value.strip().lower()
        if value.count("@") != 1 or "." not in value.rsplit("@", 1)[-1]:
            raise ValueError("Enter a valid email address")
        return value

    @field_validator("display_name", "workspace_name")
    @classmethod
    def trim_required_names(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("This field cannot be blank")
        return value


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return value.strip().lower()


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    display_name: str
    is_active: bool
    created_at: datetime


class WorkspaceRead(BaseModel):
    id: str
    name: str
    role: WorkspaceRole
    created_at: datetime


class AuthResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
    user: UserRead
    workspace: WorkspaceRead




class InvitationCreate(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    role: Literal["admin", "analyst", "viewer"] = "analyst"

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        value = value.strip().lower()
        if value.count("@") != 1 or "." not in value.rsplit("@", 1)[-1]:
            raise ValueError("Enter a valid email address")
        return value


class InvitationRead(BaseModel):
    id: str
    email: str
    role: WorkspaceRole
    expires_at: datetime
    created_at: datetime


class InvitationCreated(InvitationRead):
    invite_token: str


class InvitationAccept(BaseModel):
    invite_token: str = Field(min_length=32, max_length=256)


class MembershipRoleUpdate(BaseModel):
    role: WorkspaceRole


class AuditLogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    workspace_id: str | None
    actor_user_id: str | None
    action: str
    target_type: str | None
    target_id: str | None
    details: dict
    created_at: datetime


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

    @field_validator("message")
    @classmethod
    def trim_message(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("message must contain a non-whitespace character")
        return value

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
    workspace_id: str
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
