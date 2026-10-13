# Watchtower

**Watchtower** is a long-term, modular Security Operations Center (SOC) platform built for security event collection, detection engineering, threat hunting, incident response, and digital forensics.

This is a new project, separate from Sentinel. It will be developed incrementally, with tested milestones and documented design decisions.

## Project status

**Milestone 1 — Foundation (implementation started)**

The initial API supports health checks, normalized security-event ingestion, persistent storage, and filtered event retrieval. PostgreSQL is the intended primary database; SQLite is the zero-configuration local development default.

## Public website (GitHub Pages)

The repository includes a static public landing page and an interactive demo using fictional sample events. It does not connect to the API or collect visitor data.

To publish it for free:

1. Open the repository's **Settings → Pages**: https://github.com/btwsalts/watchtower/settings/pages
2. Under **Build and deployment**, choose **GitHub Actions** as the source.
3. Save the setting. The workflow in `.github/workflows/pages.yml` will deploy the site after a push to `main`; you can also run it from **Actions → Deploy Watchtower public website → Run workflow**.
4. Wait for the workflow to finish, then open the URL shown in the deployment job. It should be `https://btwsalts.github.io/watchtower/` for this repository, unless GitHub shows a different URL.

The first deployment may require that one-time Pages setting in repository settings. The public website is separate from the FastAPI backend; GitHub Pages cannot host the Python API or PostgreSQL database.

## Current capabilities

- Health and database-readiness endpoints
- Validated security-event ingestion
- UTC timestamp normalization and event-type normalization
- SQLite for local development; PostgreSQL through configuration
- Event listing with severity, event type, and source IP filters
- Bounded pagination
- API tests and Docker Compose development services

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

The API listens on `http://127.0.0.1:8000`. The local SQLite database is created as `watchtower.db` in the current working directory.

Open the interactive API documentation at `http://127.0.0.1:8000/docs`.

## Run tests

```bash
pytest -q
```

## Run with PostgreSQL using Docker Compose

Docker Compose publishes the API on localhost only. The database is kept on the internal Compose network.

```bash
docker compose up --build
```

The default Compose password is for local development only. Set a strong `POSTGRES_PASSWORD` in your shell or local environment before using this stack beyond a disposable local environment. Do not expose this development deployment directly to the internet.

## API quick start

Check process health:

```bash
curl http://127.0.0.1:8000/healthz
```

Check database readiness:

```bash
curl http://127.0.0.1:8000/readyz
```

Submit a sample event:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/events \
  -H 'Content-Type: application/json' \
  -d '{
    "event_type": "SSH Brute-Force",
    "source": "linux-agent",
    "hostname": "lab-linux-01",
    "source_ip": "192.0.2.10",
    "username": "test-user",
    "severity": "high",
    "message": "Repeated failed SSH logins",
    "raw_event": {"attempts": 8}
  }'
```

List events, or filter by event type and severity:

```bash
curl 'http://127.0.0.1:8000/api/v1/events?limit=50'
curl 'http://127.0.0.1:8000/api/v1/events?event_type=ssh-brute-force&severity=high'
```

## Planned capabilities

- Rule-based detection and alert lifecycle
- Analyst dashboard and incident management
- Linux and Windows endpoint agents
- Network telemetry and detection
- Threat-intelligence enrichment and MITRE ATT&CK mapping
- Investigation timelines and forensic evidence
- Controlled attack simulation and lab-only response automation

See [the roadmap](docs/ROADMAP.md) for milestones.

## Safety

Watchtower is intended for authorized defensive monitoring and isolated lab testing. The initial API is a development foundation, not a production-secure deployment: authentication, authorization, agent identity, rate limiting, database migrations, and audit controls must be implemented before exposing it to untrusted networks. Response actions must be explicitly configured and scoped to systems the operator is authorized to administer.
