# Watchtower

**Watchtower** is a modular Security Operations Center (SOC) platform for security event collection, detection engineering, threat hunting, incident response, and digital forensics. It is a separate project from Sentinel and is built in tested milestones.

## Project status

**Milestone 2 — Accounts, workspace isolation, and initial access management**

The API now includes account registration and login, expiring signed bearer tokens, Argon2 password hashing, private workspaces, member invitations, role checks, workspace-scoped event access, and audit records for important actions.

## Public website

- Landing page: https://btwsalts.github.io/watchtower/
- Demo dashboard: https://btwsalts.github.io/watchtower/dashboard.html
- Sign in / sign up: https://btwsalts.github.io/watchtower/auth.html
- Authenticated workspace portal: https://btwsalts.github.io/watchtower/app.html
- Repository: https://github.com/btwsalts/watchtower

The demo dashboard uses fictional data. The sign-in and sign-up interface is published, but real authentication requires the backend to be deployed and its URL configured in `api-config.js`. The API is not yet deployed as a public service.

## Current API capabilities

- Health and database-readiness endpoints
- Account registration and login
- Argon2 password hashing through pwdlib
- Signed JWT bearer access tokens with expiration
- Workspace membership and owner role on registration
- Workspace selection through the `X-Workspace-ID` header
- Single-use, seven-day workspace invitations (manual secure token delivery; no email service yet)
- Workspace member listing and role changes
- Owner/admin-only audit log viewing
- Workspace-scoped event ingestion and retrieval
- Role restrictions: owners/admins/analysts can ingest; viewers are read-only
- Severity, event type, and source IP filters with bounded pagination
- Configurable CORS for the browser frontend
- SQLite for local development; PostgreSQL through configuration

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

The API listens on `http://127.0.0.1:8000`; the local SQLite database is `watchtower.db`. Interactive API documentation is at `http://127.0.0.1:8000/docs`.

For the browser pages, edit `api-config.js` and set:

```javascript
window.WATCHTOWER_API_URL = "http://127.0.0.1:8000";
```

Serve the static site through a local HTTP server (not by opening the HTML file directly), and keep the API bound to localhost while testing. Never publish real secrets in `api-config.js`; it is public frontend configuration and should contain only the API origin.

## Run tests

```bash
pytest -q
```

## Run with PostgreSQL using Docker Compose

```bash
export POSTGRES_PASSWORD="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export WATCHTOWER_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export APP_ENV=production
docker compose up --build
```

Compose binds the API to localhost only. Set `WATCHTOWER_CORS_ORIGINS` to a comma-separated list of trusted frontend origins if your site uses a different origin. Do not expose this development stack directly to the public internet.

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

The response contains an access token and workspace ID. Passwords must be at least 12 characters. Treat access tokens as secrets.

## Event API example

Replace `ACCESS_TOKEN` and `WORKSPACE_ID` with values returned by registration or login.

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
```

## Roles and invitations

- **Owner:** created on registration; can manage workspace access and view audit records.
- **Admin:** can invite members, manage non-owner roles, and view audit records.
- **Analyst:** can read and ingest security events.
- **Viewer:** read-only event access.

Owners/admins can create invitations from the workspace portal or `POST /api/v1/workspaces/invitations`. The API returns a one-time token; send it to the invited person using a secure channel. The invitee must already have an account with the invited email, sign in, and accept the token at the workspace portal. The token is hashed at rest and expires after seven days. Automated email delivery is not implemented.

## Important limitations before public launch

This is not yet a production-ready multi-tenant service. Before accepting customer data, Watchtower still needs versioned Alembic migrations, persistent login rate limiting and abuse controls, email verification and password reset, token/session revocation, owner transfer and member removal flows, stronger invitation delivery, comprehensive audit coverage, backup/restore testing, operational monitoring, and an independent security review. The current legacy database upgrade is transitional, not a substitute for a migration system. Events from an older schema remain unassigned and are intentionally hidden from workspace queries until deliberately migrated.

## AbuseIPDB threat intelligence (initial integration)

The authenticated endpoint `GET /api/v1/threat-intel/ip/{ip_address}` enriches a public IP address using AbuseIPDB. It requires a bearer access token and the `X-Workspace-ID` header, just like other workspace endpoints.

Configure `ABUSEIPDB_API_KEY` in the API server environment (never in `api-config.js` or browser code). Without a key, the endpoint returns `503` with a configuration message. Only globally routable public IPs are sent to the provider; private, loopback, reserved, and malformed addresses are rejected. Results are normalized, cached in process for 15 minutes (up to 1,000 entries), and lookups are written to the workspace audit log. Provider rate limits and outages are returned as explicit errors rather than being treated as a clean reputation result. Cache entries are per process, so a multi-worker deployment should add shared cache storage later.

Example after signing in and obtaining a token:

```bash
curl "http://127.0.0.1:8000/api/v1/threat-intel/ip/8.8.8.8" \\
  -H "Authorization: Bearer ACCESS_TOKEN" \\
  -H "X-Workspace-ID: WORKSPACE_ID"
```

Run integration tests with `pytest -q`. Tests use mocked HTTP responses and do not need a real AbuseIPDB key or network access.

## Planned capabilities

- Detection rules and alert lifecycle
- Live detection and incident workflow
- Linux and Windows endpoint agents
- Network telemetry and detection
- Threat-intelligence enrichment and MITRE ATT&CK mapping
- Investigation timelines and forensic evidence
- Controlled attack simulation and scoped response automation

See [the roadmap](docs/ROADMAP.md).

## Safety

Use Watchtower only for systems and data you are authorized to monitor. Keep development deployments bound to localhost and do not expose the API directly to the internet. Automated response features must be explicitly scoped to authorized systems.
