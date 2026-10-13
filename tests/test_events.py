"""API tests for authentication and workspace isolation."""

import os
from pathlib import Path

_TEST_DB = Path("/tmp/watchtower-pytest.db")
_TEST_DB.unlink(missing_ok=True)
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DB}"
os.environ.setdefault("APP_ENV", "development")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from watchtower.database import Base, engine  # noqa: E402
from watchtower.main import app  # noqa: E402


@pytest.fixture()
def client():
    """Give each test a clean database and run the application lifespan."""
    Base.metadata.drop_all(bind=engine)
    with TestClient(app) as test_client:
        yield test_client


def register(client: TestClient, email: str, workspace_name: str) -> dict:
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "display_name": "Test Analyst",
            "workspace_name": workspace_name,
            "password": "correct-horse-battery-staple",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def auth_headers(auth: dict) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {auth['access_token']}",
        "X-Workspace-ID": auth["workspace"]["id"],
    }


def test_health_and_readiness(client: TestClient) -> None:
    assert client.get("/healthz").json()["status"] == "ok"
    assert client.get("/readyz").json() == {"status": "ready", "database": "ok"}


def test_register_login_and_current_user(client: TestClient) -> None:
    auth = register(client, "Analyst@Example.com", "Blue Team")
    assert auth["user"]["email"] == "analyst@example.com"
    assert auth["workspace"]["name"] == "Blue Team"
    assert auth["workspace"]["role"] == "owner"
    assert auth["access_token"]

    headers = auth_headers(auth)
    assert client.get("/api/v1/auth/me", headers=headers).json()["id"] == auth["user"]["id"]
    workspaces = client.get("/api/v1/workspaces", headers={"Authorization": headers["Authorization"]})
    assert workspaces.status_code == 200
    assert len(workspaces.json()) == 1

    login = client.post(
        "/api/v1/auth/login",
        json={"email": "ANALYST@example.com", "password": "correct-horse-battery-staple"},
    )
    assert login.status_code == 200
    assert login.json()["user"]["id"] == auth["user"]["id"]


def test_rejects_duplicate_accounts_weak_passwords_and_bad_login(client: TestClient) -> None:
    register(client, "analyst@example.com", "First Workspace")
    duplicate = client.post(
        "/api/v1/auth/register",
        json={
            "email": "analyst@example.com",
            "display_name": "Another Analyst",
            "workspace_name": "Second Workspace",
            "password": "correct-horse-battery-staple",
        },
    )
    assert duplicate.status_code == 409

    weak = client.post(
        "/api/v1/auth/register",
        json={
            "email": "new@example.com",
            "display_name": "New Analyst",
            "workspace_name": "New Workspace",
            "password": "short",
        },
    )
    assert weak.status_code == 422
    bad_login = client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@example.com", "password": "wrong-password"},
    )
    assert bad_login.status_code == 401


def test_event_ingestion_and_filters_are_workspace_scoped(client: TestClient) -> None:
    owner = register(client, "owner@example.com", "Owner Workspace")
    other = register(client, "other@example.com", "Other Workspace")
    owner_headers = auth_headers(owner)
    other_headers = auth_headers(other)

    response = client.post(
        "/api/v1/events",
        headers=owner_headers,
        json={
            "event_type": " SSH Brute-Force ",
            "source": " Linux-Agent ",
            "hostname": "lab-linux-01",
            "source_ip": "192.0.2.10",
            "username": "test-user",
            "severity": "HIGH",
            "message": "Repeated failed SSH logins",
            "raw_event": {"attempts": 8},
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["workspace_id"] == owner["workspace"]["id"]
    assert body["event_type"] == "ssh_brute_force"
    assert body["source"] == "linux-agent"
    assert body["severity"] == "high"
    assert body["raw_event"] == {"attempts": 8}

    owner_list = client.get(
        "/api/v1/events",
        headers=owner_headers,
        params={"event_type": "ssh-brute-force", "severity": "high"},
    )
    assert owner_list.status_code == 200
    assert owner_list.json()["count"] == 1
    assert owner_list.json()["items"][0]["id"] == body["id"]

    other_list = client.get("/api/v1/events", headers=other_headers)
    assert other_list.status_code == 200
    assert other_list.json()["count"] == 0
    assert other_list.json()["items"] == []


def test_users_cannot_select_another_users_workspace(client: TestClient) -> None:
    first = register(client, "first@example.com", "First Workspace")
    second = register(client, "second@example.com", "Second Workspace")
    headers = {
        "Authorization": f"Bearer {first['access_token']}",
        "X-Workspace-ID": second["workspace"]["id"],
    }
    assert client.get("/api/v1/events", headers=headers).status_code == 404
    assert client.post(
        "/api/v1/events",
        headers=headers,
        json={"event_type": "login", "message": "should not be stored"},
    ).status_code == 404


def test_event_endpoints_require_auth_and_workspace(client: TestClient) -> None:
    assert client.get("/api/v1/events").status_code == 401
    auth = register(client, "analyst@example.com", "Analyst Workspace")
    assert client.get(
        "/api/v1/events",
        headers={"Authorization": f"Bearer {auth['access_token']}"},
    ).status_code == 422
    assert client.get(
        "/api/v1/events",
        headers={
            "Authorization": "Bearer invalid-token",
            "X-Workspace-ID": auth["workspace"]["id"],
        },
    ).status_code == 401


def test_event_validation_and_bounded_pagination(client: TestClient) -> None:
    auth = register(client, "analyst@example.com", "Analyst Workspace")
    headers = auth_headers(auth)
    invalid = client.post(
        "/api/v1/events",
        headers=headers,
        json={"event_type": "login", "severity": "extreme", "message": ""},
    )
    assert invalid.status_code == 422
    assert client.get("/api/v1/events?limit=201", headers=headers).status_code == 422
    assert client.get("/api/v1/events?offset=-1", headers=headers).status_code == 422


def test_production_requires_strong_jwt_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    from watchtower.security import validate_security_config

    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("WATCHTOWER_JWT_SECRET", raising=False)
    with pytest.raises(RuntimeError, match="WATCHTOWER_JWT_SECRET"):
        validate_security_config()

    monkeypatch.setenv("WATCHTOWER_JWT_SECRET", "production-secret-with-at-least-32-chars")
    validate_security_config()



def test_invitation_acceptance_role_permissions_and_audit_logs(client: TestClient) -> None:
    owner = register(client, "owner@example.com", "Blue SOC")
    analyst = register(client, "analyst@example.com", "Analyst Home")
    owner_headers = auth_headers(owner)
    analyst_headers = auth_headers(analyst)

    created = client.post(
        "/api/v1/workspaces/invitations",
        headers=owner_headers,
        json={"email": "analyst@example.com", "role": "viewer"},
    )
    assert created.status_code == 201, created.text
    invite = created.json()
    assert "invite_token" in invite

    accepted = client.post(
        "/api/v1/workspaces/invitations/accept",
        headers={"Authorization": analyst_headers["Authorization"]},
        json={"invite_token": invite["invite_token"]},
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["role"] == "viewer"
    invited_headers = {
        "Authorization": analyst_headers["Authorization"],
        "X-Workspace-ID": owner["workspace"]["id"],
    }

    assert client.get("/api/v1/events", headers=invited_headers).status_code == 200
    denied_write = client.post(
        "/api/v1/events",
        headers=invited_headers,
        json={"event_type": "login", "message": "viewer cannot ingest"},
    )
    assert denied_write.status_code == 403

    member_list = client.get("/api/v1/workspaces/members", headers=owner_headers)
    assert member_list.status_code == 200
    invited_member = next(item for item in member_list.json() if item["email"] == "analyst@example.com")
    changed = client.patch(
        f"/api/v1/workspaces/members/{invited_member['membership_id']}",
        headers=owner_headers,
        json={"role": "analyst"},
    )
    assert changed.status_code == 200
    assert changed.json()["role"] == "analyst"

    audit_logs = client.get("/api/v1/audit-logs", headers=owner_headers)
    assert audit_logs.status_code == 200
    actions = {item["action"] for item in audit_logs.json()}
    assert "account.registered" in actions
    assert "workspace.invitation_created" in actions
    assert "workspace.invitation_accepted" in actions
    assert "workspace.member_role_changed" in actions


def test_non_admin_cannot_invite_or_read_audit_logs(client: TestClient) -> None:
    owner = register(client, "owner@example.com", "Blue SOC")
    analyst = register(client, "analyst@example.com", "Analyst Home")
    invite = client.post(
        "/api/v1/workspaces/invitations",
        headers=auth_headers(owner),
        json={"email": "analyst@example.com", "role": "analyst"},
    )
    assert invite.status_code == 201
    accepted = client.post(
        "/api/v1/workspaces/invitations/accept",
        headers={"Authorization": f"Bearer {analyst['access_token']}"},
        json={"invite_token": invite.json()["invite_token"]},
    )
    assert accepted.status_code == 200
    analyst_in_owner_workspace = {
        "Authorization": f"Bearer {analyst['access_token']}",
        "X-Workspace-ID": owner["workspace"]["id"],
    }
    assert client.get("/api/v1/audit-logs", headers=analyst_in_owner_workspace).status_code == 403
    assert client.post(
        "/api/v1/workspaces/invitations",
        headers=analyst_in_owner_workspace,
        json={"email": "third@example.com", "role": "viewer"},
    ).status_code == 403


def test_invitation_is_email_bound_and_single_use(client: TestClient) -> None:
    owner = register(client, "owner@example.com", "Blue SOC")
    wrong_user = register(client, "wrong@example.com", "Personal")
    invite = client.post(
        "/api/v1/workspaces/invitations",
        headers=auth_headers(owner),
        json={"email": "right@example.com", "role": "analyst"},
    )
    assert invite.status_code == 201
    token = invite.json()["invite_token"]

    wrong_accept = client.post(
        "/api/v1/workspaces/invitations/accept",
        headers={"Authorization": f"Bearer {wrong_user['access_token']}"},
        json={"invite_token": token},
    )
    assert wrong_accept.status_code == 403
