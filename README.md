# Watchtower

**Watchtower** is a long-term, modular Security Operations Center (SOC) platform built for security event collection, detection engineering, threat hunting, incident response, and digital forensics.

This is a new project, separate from Sentinel. It will be developed incrementally, with tested milestones and documented design decisions.

## Project status

**Milestone 1 — Foundation (in progress)**

The first milestone establishes a backend API for health checks and normalized security-event ingestion and retrieval. PostgreSQL is the intended primary database; a local SQLite default keeps initial development easy.

## Planned capabilities

- Security event ingestion, normalization, storage, and search
- Rule-based detection and alert lifecycle
- Analyst dashboard and incident management
- Linux and Windows endpoint agents
- Network telemetry and detection
- Threat-intelligence enrichment and MITRE ATT&CK mapping
- Investigation timelines and forensic evidence
- Controlled attack simulation and lab-only response automation

## Development

Requirements and setup instructions will be added as the initial backend is implemented.

## Safety

Watchtower is intended for authorized defensive monitoring and isolated lab testing. Response actions must be explicitly configured and scoped to systems the operator is authorized to administer.
