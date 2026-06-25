# Changelog

All notable changes to the Audit extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-06-25

Initial release — an event-sourced, append-only audit trail.

### Added
- **`audit_logs` table + migration.** One normalized row shape (`occurred_at`,
  `actor_uuid`/`actor_label`, `action`, `category`, `target_type`/`target_uuid`/`target_label`,
  `changes`, `context`), indexed for the global feed, per-actor, and per-target queries. No FKs
  (soft references to actors/targets in other packages).
- **`AuditSubscriber`** — records framework entity writes (`EntityCreatedEvent` / `EntityUpdatedEvent` /
  `EntityDeletedEvent` → `created` / `updated` / `deleted`) and auth/security events (`login`,
  `login_failed`, `logout`, `rate_limit_exceeded`, `security_violation`). The actor is resolved from the
  current request's authenticated principal (the always-present `'user'` attribute); CLI/system writes
  record `actor = system`. Deletes record `changes = null` (no full snapshot); updates carry a redacted
  before/after diff.
- **`AegisAuditSubscriber` (optional)** — when `glueful/aegis` is installed, records the six RBAC domain
  events *semantically* (`role_assigned`, `role_revoked`, `permission_assigned`, `permission_revoked`,
  `role_permission_assigned`, `role_permission_revoked`) with the role/permission slug + any resource
  filter/expiry in `context`, instead of raw `user_roles` pivot writes. Aegis is a **soft dependency**:
  absent it (or with `capture.rbac = false`), the subscriber isn't registered and audit still records
  core/auth/entity events. The RBAC assignment pivots are suppressed from generic capture only while the
  semantic subscriber is active (no double-recording; no silent drop).
- **Read-only HTTP API** — `GET /v1/audit-logs` (filter by `actor`/`action`/`category`/`target_type`/
  `target_uuid`/`from`/`to`, paginated) and `GET /v1/audit-logs/{uuid}`, both gated by the new
  `audit.view` permission. Append-only — no write/update/delete routes.
- **`audit:prune` retention command** + `config/audit.php` (kill-switch, capture toggles, ignore/pivot
  table lists, redaction patterns, retention horizon).
- **Safeguards:** a raw-insert recursion guard (the recorder never uses `BaseRepository`, so an audit
  write can't audit itself), recursive sensitive-field redaction in `changes`/`context`, an auth-event
  token allow-list (no access/refresh token value can reach a row), and best-effort, non-throwing
  recording (an audit failure never breaks the audited operation).

### Requirements
- `glueful/framework >=1.63.0` (for `EntityDeletedEvent` + the protected `BaseRepository::dispatchEvent()`).
- Suggests `glueful/aegis >=1.13.0` for semantic RBAC audit rows (optional).
