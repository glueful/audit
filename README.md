# Glueful Audit

An event-sourced, append-only **audit trail** for Glueful apps: it records "actor X
did action Y to target Z at time T" as normalized rows, fed automatically from
framework and extension domain events, and exposes them through a single filtered,
read-only HTTP API.

Audit answers one question: **"who did what, to which entity, when?"** It is a
business/compliance record — distinct from the framework's operational
`activity_logs` (Monolog DB logging). Different shape, retention, immutability, and
access control.

## Install

```bash
composer require glueful/audit
php glueful extensions:enable audit
php glueful migrate:run
```

Requires `glueful/framework >=1.63.0` (for `EntityDeletedEvent` and the protected
`BaseRepository::dispatchEvent()` seam). The migration creates one table,
`audit_logs`. The extension records nothing until enabled; once enabled,
`AUDIT_ENABLED` is a runtime kill-switch (default on).

**Optional:** `composer require glueful/aegis` (`>=1.13.0`) to record RBAC actions
*semantically* (see [RBAC auditing](#rbac-auditing-optional)). Audit works fully
without it.

## How it works

Audit is **event-sourced** — it never asks controllers to call an `audit()` helper.
A subscriber listens to a curated set of events and writes a normalized row for each:

```
domain events ──▶ AuditSubscriber ──▶ AuditRecorder ──▶ audit_logs (append-only)
(EntityCreated/Updated/Deleted,         (resolves actor from the request,
 auth/security, + RBAC if Aegis)         redacts secrets, raw-inserts — no
                                         BaseRepository, so it can't audit itself)
```

The **actor** (the *who*) isn't carried by entity events, so the subscriber resolves
it from the current request's authenticated principal at event time; CLI/system
writes record `actor = system`.

## What gets recorded

Each row is one normalized shape:

| Column | Meaning |
| --- | --- |
| `occurred_at` | event time (indexed) |
| `actor_uuid` / `actor_label` | who (uuid + cached email/username; `system` for CLI) |
| `action` | the verb (see table below) |
| `category` | `auth` · `rbac` · `user` · `content` · `security` · `data` |
| `target_type` / `target_uuid` / `target_label` | what was acted on |
| `changes` | JSON `{field: {from, to}}` for updates (redacted); `null` otherwise |
| `context` | JSON `{ip, user_agent, request_id, …}` |

Indexed for the three queries that matter: the global feed, "everything actor X
did," and "the history of this target."

### Sources and actions

| Source | Actions |
| --- | --- |
| Entity writes (`BaseRepository` create/update/delete) | `created` · `updated` · `deleted` |
| Auth events | `login` · `login_failed` · `logout` |
| Security events | `rate_limit_exceeded` · `security_violation` |
| RBAC (with Aegis) | `role_assigned` · `role_revoked` · `permission_assigned` · `permission_revoked` · `role_permission_assigned` · `role_permission_revoked` |
| App / extension events (`AuditableEvent`) | whatever the event declares — see [Recording your own events](#recording-your-own-events) |

A delete records *that* it happened (`changes = null`, label from the pre-delete
record) — never a full snapshot, to limit retention/privacy exposure. Updates carry
a redacted before/after diff.

## RBAC auditing (optional)

Generic table events would render RBAC as noise — `created user_roles`. With
`glueful/aegis` installed, audit instead subscribes to Aegis's semantic RBAC events
and records readable rows — *"actor assigned `editor` to Jane"* — with the role /
permission uuid + slug and any resource filter / expiry in `context`.

- For grants/revokes **to a user**, the target is the **user** (so a user's access
  history is one filter); for **role↔permission** links, the target is the **role**.
- Aegis is a **soft dependency**: if it's absent (or `capture.rbac = false`), the
  RBAC subscriber simply isn't registered and audit keeps recording core/auth/entity
  events. To avoid double-recording, the RBAC assignment pivots
  (`user_roles`, `user_permissions`, `role_permissions`) are suppressed from generic
  capture **only while** the semantic subscriber is active.

## Recording your own events

Most app/extension writes don't go through `BaseRepository` (so they emit no entity event)
and aren't auth/RBAC — content publishes, exports, billing, imports. To audit those, make the
event **self-auditing**: implement `Glueful\Extensions\Audit\Contracts\AuditableEvent`. Any
implementer dispatched on the framework event bus is recorded automatically — no subscriber,
no reference to the recorder. The audit subscriber fills in the actor and request context
(`ip` / `user_agent` / `request_id` / `event_id`); your event supplies the rest.

```php
use Glueful\Events\Contracts\BaseEvent;
use Glueful\Extensions\Audit\Contracts\{AuditableEvent, AuditableEventDefaults};

final class EntryPublished extends BaseEvent implements AuditableEvent
{
    use AuditableEventDefaults; // defaults for target/changes/metadata — override as needed

    public function __construct(
        public readonly string $entryUuid,
        public readonly string $title,
    ) {
        parent::__construct();
    }

    public function auditAction(): string   { return 'published'; }
    public function auditCategory(): string { return 'content'; }
    public function auditTarget(): array
    {
        return ['type' => 'content_entry', 'uuid' => $this->entryUuid, 'label' => $this->title];
    }
}

// Anywhere you already dispatch events:
$this->events->dispatch(new EntryPublished($uuid, $title));
```

`AuditableEvent` is a tiny contract: `auditAction()`, `auditCategory()`, `auditTarget()`,
`auditChanges()` (`{field: {from, to}}` for updates), and `auditMetadata()` (merged into
`context`, redacted by the same `redact_fields` rules). The `AuditableEventDefaults` trait
supplies no-op defaults so a simple event only defines the first two. The whole group can be
turned off with `capture.custom = false`.

**Without the marker interface.** If you'd rather not couple an event to this package, depend
on the `Glueful\Extensions\Audit\Contracts\AuditRecorderInterface` service instead and record
from your own subscriber:

```php
app($context, AuditRecorderInterface::class)->record(new AuditEntry(
    occurredAt: microtime(true),
    action: 'exported',
    category: 'data',
    // … actor/target/changes/context …
));
```

## Read API

Append-only — there are no write/update/delete routes. Both routes require the
`audit.view` permission.

```
GET /v1/audit-logs            # filtered, paginated list
GET /v1/audit-logs/{uuid}     # one row
```

`index` filters (all optional): `actor`, `action`, `category`, `target_type`,
`target_uuid`, `from`, `to` (ISO timestamps), `page`, `per_page`. The response is the
framework's flat paginated envelope (`data`, `current_page`, `per_page`, `total`,
`total_pages`, …), ordered newest-first.

```bash
GET /v1/audit-logs?actor=<uuid>&action=role_assigned&from=2026-06-01&to=2026-06-30
```

## Permissions

The extension declares one permission via the framework's permission catalog:

| Permission | Gates |
| --- | --- |
| `audit.view` | reading the audit log (`GET /v1/audit-logs*`) |

## Configuration (`config/audit.php`)

| Key | Env | Default | Purpose |
| --- | --- | --- | --- |
| `enabled` | `AUDIT_ENABLED` | `true` | runtime kill-switch (recording) |
| `routes_enabled` | `AUDIT_ROUTES_ENABLED` | `true` | mount the read API |
| `capture.{entities,auth,security,rbac}` | — | `true` | per-source toggles |
| `ignore_tables` | — | session/cache/log/token tables | tables the generic subscriber never records |
| `rbac_pivot_tables` | — | the three RBAC pivots | suppressed only when RBAC is captured semantically |
| `redact_fields` | — | `password`, `*_token`, `secret`, `api_key`, … | field-name patterns redacted in `changes`/`context` |
| `retention_days` | `AUDIT_RETENTION_DAYS` | `365` | prune horizon |

## Retention

```bash
php glueful audit:prune        # delete rows older than retention_days
```

Schedule it from your app's scheduler (the extension ships the command, not the
schedule).

## Safeguards

- **Recursion guard.** The recorder writes via a raw `Connection` insert — never
  `BaseRepository::create()` — so an audit write dispatches no event and can't audit
  itself; the subscriber also hard-skips the `audit_logs` table.
- **Redaction.** `changes`/`context` are recursively scrubbed of secret-looking
  fields (`password`, `*_token`, …) before the row is written.
- **No tokens, ever.** Auth handlers build their rows from an explicit field
  allow-list and never read the session token accessors — no access/refresh token
  value can reach a row.
- **Best-effort.** A failed audit write is logged and swallowed; it never breaks the
  operation being audited.

## What it is not

- Not the operational log. `activity_logs` (Monolog) is for app/security *logging*;
  this is a business *record*.
- Not a write API. It's append-only — rows are produced by events, read by the API,
  pruned by retention. Nothing edits or deletes individual rows.
- Not an RBAC editor. It *records* role/permission changes; managing them stays in
  Aegis.
