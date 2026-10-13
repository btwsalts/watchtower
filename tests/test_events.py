"""API tests for the first Watchtower milestone."""

import os
from pathlib import Path

# Use an isolated file-backed SQLite database for the test process.
_TEST_DB = Path("/tmp/watchtower-pytest.db")
_TEST_DB.unlink(missing_ok=True)
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DB}"

from fastapi.testclient import TestClient  # noqa: E402
from watchtower.main import app  # noqa: E402


with TestClient(app) as client:
    def test_health_and_readiness() -> None:
        assert client.get("/healthz").json()["status"] == "ok"
        assert client.get("/readyz").json() == {"status": "ready", "database": "ok"}

    def test_ingest_normalizes_and_persists_event() -> None:
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

    def test_rejects_invalid_severity_and_empty_message() -> None:
        response = client.post(
            "/api/v1/events",
            json={"event_type": "login", "severity": "extreme", "message": ""},
        )
        assert response.status_code == 422

    def test_event_list_pagination_is_bounded() -> None:
        assert client.get("/api/v1/events?limit=201").status_code == 422
        assert client.get("/api/v1/events?offset=-1").status_code == 422
