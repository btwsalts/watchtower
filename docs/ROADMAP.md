# Watchtower roadmap

## Milestone 1 — Foundation (current)

- [x] Establish repository and package layout
- [x] Define a normalized security-event schema
- [x] Implement health and readiness endpoints
- [x] Implement event ingestion and filtered retrieval
- [x] Add basic API tests
- [ ] Run tests in the target development environment
- [ ] Add database migrations before schema evolution
- [ ] Document local setup and API examples

## Milestone 2 — Detection and alerts

- [ ] Define a versioned detection-rule format
- [ ] Implement a deterministic rule evaluator
- [ ] Add SSH brute-force detection using a configurable time window
- [ ] Persist alerts and link them to source events
- [ ] Add unit tests for true positives, boundaries, and false-positive cases

## Milestone 3 — Analyst workflow

- [ ] Alert triage and status lifecycle
- [ ] Incident records, evidence, notes, and timeline
- [ ] Search filters and audit trail

## Later capabilities

- Endpoint agents (Linux first, then Windows)
- Network telemetry and detection
- Threat-intelligence enrichment and MITRE ATT&CK mapping
- Threat hunting and digital-forensics workflows
- Controlled attack simulation
- Lab-scoped SOAR and response actions
- Analyst dashboard and role-based access control

## Engineering principles

1. Every milestone must be runnable and tested before expansion.
2. Keep ingestion, storage, detection, and response as separate modules.
3. Never enable destructive response actions by default.
4. Treat incoming event payloads as untrusted data.
5. Do not expose the development API directly to the public internet.
