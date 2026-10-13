# Watchtower

**Watchtower** is a modular Security Operations Center (SOC) platform for security event collection, detection engineering, threat hunting, incident response, and digital forensics. It is a separate project from Sentinel and is being built in tested milestones.

## Project status

**Milestone 2 — Accounts and workspace isolation (implementation started)**

The API foundation includes account registration and login, signed bearer access tokens, password hashing, workspace membership, and workspace-scoped event ingestion and retrieval. This is an early development implementation, not yet ready for public customer data.

## Public website

- Landing page: https://btwsalts.github.io/watchtower/
- SOC dashboard preview: https://btwsalts.github.io/watchtower/dashboard.html
- Browser favicon: `favicon.svg`

The public dashboard is a static demo using fictional data. It does not connect to the API or collect visitor data.

## Current API capabilities

- Health and database-readiness endpoints
- Account registration and login
- Argon2 password hashing through pwdlib
- Signed JWT bearer access tokens with expiration
- Workspace membership and owner role on registration
- Workspace selection via the `X-Workspace-ID` request header
- Workspace-scoped event ingestion and retrieval
- Severity, event type, and source IP filters with bounded pagination
- SQLite for local development; PostgreSQL via configuration
- Tests and Docker Compose development services

## Run locally on Linux

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
uvicorn watchtower.main:app --reload
```

The API listens on `http://127.0.0.1:8000`. SQLite creates `watchtower.db` in the working directory. API documentation is available at `http://127.0.0.1:8000/docs`.

## Run tests

```bash
pytest -q
```

## Register an account

```bash
curl -X POST http://127.0.0.1:8000/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "analyst@example.com",
    "display_name": "SOC Analyst",
    "workspace_name": "My SOC",
    "password": "replace-this-with-a-long-unique-password"
  }'
```

The response contains an access token and the new workspace ID. Treat the token as a secret. Passwords must be at least 12 characters.

## Log in

```bash
curl -X POST http://127.0.0.1:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"analyst@example.com","password":"replace-this-with-a-long-unique-password"}'
```

## Submit and list workspace events

Replace `ACCESS_TOKEN` and `WORKSPACE_ID` with the values returned by registration or login.

```bash
curl -X POST http://127.0.0.1:8000/api/v1/events \
  -H 'Authorization: Bearer ACCESS_TOKEN' \
  -H 'X-Workspace-ID: WORKSPACE_ID' \
  -H 'Content-Type: application/json' \
  -d '{
    "event_type": "SSH Brute-Force",
    "source": "linux-agent",
    "hostname": "lab-linux-01",
    "source_ip": "192.0.2.10",
    "severity": "high",
    "message": "Repeated failed SSH logins",
    "raw_event": {"attempts": 8}
  }'

curl http://127.0.0.1:8000/api/v1/events \
  -H 'Authorization: Bearer ACCESS_TOKEN' \
  -H 'X-Workspace-ID: WORKSPACE_ID'
```

A user must be a member of the selected workspace. The API scopes event queries to that workspace; choosing another user's workspace ID does not grant access.

## PostgreSQL with Docker Compose

```bash
export POSTGRES_PASSWORD="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export WATCHTOWER_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
docker compose up --build
```

Compose binds the API to localhost only. The default JWT secret and database password in Compose are development defaults: override both for any shared environment. To enable production configuration checks, set `APP_ENV=production` and supply `WATCHTOWER_JWT_SECRET` with at least 32 random characters.

## Important limitations before public launch

This milestone is not a complete multi-tenant production service. Before accepting real customer data, Watchtower still needs formal versioned database migrations, rate limiting, login abuse controls, email verification and password reset, workspace member invitation and role-management endpoints, audit logging, secret rotation, backup/restore testing, operational monitoring, and a security review. Existing events from a pre-workspace database are kept unassigned during upgrade and are not returned to workspace users; migrate them deliberately if they need to be retained.

## Planned capabilities

- Detection rules and alert lifecycle
- Live analyst dashboard and incident management
- Linux and Windows endpoint agents
- Network telemetry and detection
- Threat-intelligence enrichment and MITRE ATT&CK mapping
- Investigation timelines and forensic evidence
- Controlled attack simulation and scoped response automation

See [the roadmap](docs/ROADMAP.md).

## Safety

Use Watchtower only for systems and data you are authorized to monitor. Keep development deployments bound to localhost and do not expose the API directly to the internet. Automated response features must be explicitly scoped to authorized systems.
