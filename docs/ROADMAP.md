# Watchtower roadmap

## Milestone 1 — API foundation

- [x] Establish repository and package layout
- [x] Define a normalized security-event schema
- [x] Implement health and readiness endpoints
- [x] Implement event ingestion and filtered retrieval
- [x] Add automated API tests and CI workflow
- [ ] Verify the workflow result on GitHub Actions
- [ ] Replace the transitional schema upgrade with versioned Alembic migrations before production

## Milestone 2 — Accounts and workspace isolation (current)

- [x] Register an account and create its first workspace
- [x] Hash passwords with Argon2
- [x] Issue expiring signed bearer access tokens
- [x] Authenticate requests and expose the current account
- [x] List only workspaces the account belongs to
- [x] Require workspace membership for event API access
- [x] Scope event writes and reads to the selected workspace
- [x] Add tests for authentication and cross-workspace isolation
- [x] Add browser sign-in/sign-up and authenticated workspace portal
- [x] Add member invitations and workspace role management
- [x] Add initial audit trail for account, invitation, role, and event actions
- [x] Configure CORS for the browser frontend
- [ ] Add login rate limiting and abuse monitoring
- [ ] Add invitation email delivery, member removal, and owner transfer
- [ ] Add more complete role-based permissions for future detections and incidents
- [ ] Add email verification, password reset, and session/token revocation
- [ ] Expand audit coverage, add login rate limiting, and complete a security review
- [ ] Replace transitional schema upgrade with versioned Alembic migrations
- [ ] Deploy the API and configure the public frontend endpoint

## Milestone 3 — Detection and alerts

- [ ] Define a versioned detection-rule format
- [ ] Implement a deterministic rule evaluator
- [ ] Add SSH brute-force detection using a configurable time window
- [ ] Persist alerts and link them to source events
- [ ] Add tests for true positives, boundaries, and false-positive cases

## Milestone 4 — Analyst workflow

- [ ] Alert triage and status lifecycle
- [ ] Incident records, evidence, notes, and timeline
- [ ] Search filters, audit trail, and dashboard API integration

## Later capabilities

- Endpoint agents (Linux first, then Windows)
- Network telemetry and detection
- Threat-intelligence enrichment and MITRE ATT&CK mapping
- Threat hunting and digital-forensics workflows
- Controlled attack simulation
- Lab-scoped SOAR and response actions

## Engineering principles

1. Every milestone must be runnable and tested before expansion.
2. Keep ingestion, storage, detection, and response as separate modules.
3. Never enable destructive response actions by default.
4. Treat incoming event payloads as untrusted data.
5. Do not expose the development API directly to the public internet.
6. Enforce workspace authorization in the API, not only in the interface.
