"""API tests for the first Watchtower milestone."""

import os
from pathlib import Path

# Use an isolated file-backed SQLite database for the test process.
_TEST_DB = Path("/tmp/watchtower-pytest.db")
_TEST_DB.unlink(missing_ok=True)
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DB}"

from fastapi.testclient import TestClient  # noqa: E402
import pytest  # noqa: E402
from watchtower.main import app  # noqa: E402


@pytest.fixture()
def client():
    """Start and stop the app lifespan for each test."""
    with TestClient(app) as test_client:
        yield test_client


def test_health_and_readiness(client: TestClient) -> None:
    assert client.get("/healthz").json()["status"] == "ok"
    assert client.get("/readyz").json() == {"status": "ready", "database": "ok"}


def test_ingest_normalizes_and_persists_event(client: TestClient) -> None:
    response = client.post(
        "/api/v1/events",
        json={
            "event_type": " SSH Brute-Force ",
            "source": " Linux-Agent ",
            "hostname": "lab-linux-01",
            "source_ip": "192.0.2.10",
            "username": "analyst-test",
            "severity": "HIGH",
            "message": "Repeated failed SSH logins",
            "raw_event": {"attempts": 8},
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["event_type"] == "ssh_brute_force"
    assert body["source"] == "linux-agent"
    assert body["severity"] == "high"
    assert body["raw_event"] == {"attempts": 8}
    assert body["id"]

    listed = client.get("/api/v1/events", params={"event_type": "ssh-brute-force", "severity": "high"})
    assert listed.status_code == 200
    result = listed.json()
    assert result["count"] == 1
    assert result["items"][0]["id"] == body["id"]


def test_rejects_invalid_severity_and_empty_message(client: TestClient) -> None:
    response = client.post(
        "/api/v1/events",
        json={"event_type": "login", "severity": "extreme", "message": ""},
    )
    assert response.status_code == 422


def test_event_list_pagination_is_bounded(client: TestClient) -> None:
    assert client.get("/api/v1/events?limit=201").status_code == 422
    assert client.get("/api/v1/events?offset=-1").status_code == 422


def test_configured_api_token_protects_event_endpoints(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    token = "test-only-token-with-at-least-32-characters"
    monkeypatch.setenv("WATCHTOWER_API_TOKEN", token)
    monkeypatch.setenv("APP_ENV", "development")

    assert client.get("/api/v1/events").status_code == 401
    assert client.get("/api/v1/events", headers={"Authorization": "Bearer wrong-token"}).status_code == 401

    headers = {"Authorization": f"Bearer {token}"}
    created = client.post(
        "/api/v1/events",
        headers=headers,
        json={"event_type": "token-auth-check", "message": "Test event"},
    )
    assert created.status_code == 201
    assert client.get("/api/v1/events", headers=headers).status_code == 200


def test_production_requires_long_api_token(monkeypatch: pytest.MonkeyPatch) -> None:
    from watchtower.security import validate_security_config

    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("WATCHTOWER_API_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="Production requires WATCHTOWER_API_TOKEN"):
        validate_security_config()

    monkeypatch.setenv("WATCHTOWER_API_TOKEN", "short")
    with pytest.raises(RuntimeError, match="Production requires WATCHTOWER_API_TOKEN"):
        validate_security_config()

    monkeypatch.setenv("WATCHTOWER_API_TOKEN", "production-token-that-is-at-least-32-chars")
    validate_security_config()
