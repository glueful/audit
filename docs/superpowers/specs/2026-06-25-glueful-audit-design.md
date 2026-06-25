# glueful/audit — Event-Sourced Audit Trail — Design

**Goal:** An opt-in Glueful extension that records a **normalized, append-only audit trail** —
"actor X did action Y to target Z at time T" — fed automatically from framework domain events, and
exposed through a single filtered read endpoint that powers an admin Audit Log view (and per-user
activity feeds).

**Status:** Design — for review before the implementation plan.

**Acceptance test:** with the extension enabled, performing auditable actions (a login, a failed
login, creating/updating/deleting a user, assigning a role to a user) produces normalized rows in
`audit_logs` — including a readable `role_assigned` row ("actor assigned <role> to <user>"), not raw
`created user_roles`. `GET /v1/audit-logs?actor=<uuid>&action=role_assigned&from=…&to=…` returns them
filtered + paginated, gated by `audit.view`; and the audit writer never audits itself.

---

## The MVP spans three repos

This is deliberately a 3-piece V1 so the audit feed is *readable* on day one — especially in the most
security-sensitive area (RBAC), where generic table events would read like database noise
(`created user_roles`, `deleted role_permissions`) instead of "Michael assigned Admin to Jane".

1. **Framework (`glueful/framework`):** add `EntityDeletedEvent` + dispatch from `BaseRepository::delete()`
   — [Bundled core change](#bundled-core-change-entitydeletedevent).
2. **Aegis (`glueful/aegis`):** add RBAC **semantic domain events** (role/permission assigned/revoked)
   — [Bundled Aegis change](#bundled-aegis-change-rbac-domain-events). **Optional integration** — audit
   does *not* hard-require Aegis.
3. **Audit extension (this repo):** the normalized store, recorder, read API, and subscribers for
   core/auth/entity events plus (when Aegis is present) the RBAC domain events.

## Why an extension (not core, not app-owned)

Per Glueful's core/extension boundary, core ships **primitives and contracts** and stays zero-infra.
A full audit *store + read API + retention* is opt-in infrastructure many apps won't enable — that's
an extension. Core already emits most of the events this extension needs (`EntityCreatedEvent`,
`EntityUpdatedEvent`, the auth/security events the framework's `ActivityLoggingSubscriber` consumes),
so the extension mostly *subscribes*. The two bundled producers (core `EntityDeletedEvent`, Aegis RBAC
events) are small, isolated event additions — not infra. The extension is reusable (unlike app-owning
it in Lemma) and the same endpoint serves Lemma's Audit Log page and the deferred Users "Activity tab".

This is distinct from `activity_logs` (the framework's Monolog DB handler — operational logging,
shaped level/channel/message/context). The audit trail is a **business record** with its own table,
shape, retention, immutability, and access control. We do **not** overload `activity_logs`.

## Architecture

```
domain events ──▶ AuditSubscriber ──▶ AuditRecorder ──▶ audit_logs (append-only)
(EntityCreated/Updated,                  │  (resolves actor from request context,
 auth/security events)                   │   maps event→normalized row, redacts secrets,
                                         │   writes via a RAW insert — never BaseRepository,
                                         │   so it can't event-loop on itself)
                                         ▼
                            GET /v1/audit-logs  (filtered, paginated, audit.view)
```

- **Event-sourced, not call-sited.** One `AuditSubscriber` (implementing
  `Glueful\Events\EventSubscriberInterface`) listens to a curated set of events and writes rows. No
  `audit(...)` calls scattered across controllers — that's the pattern that rots.
- **Append-only.** No update/delete/PUT routes. Immutability is the point.
- **Actor resolved at event time.** Entity events carry the *what* (table, entity, changes) but not
  the *who*; the subscriber resolves the current authenticated actor from the request context when the
  event fires.

## Scope

**In (MVP):**
1. **Core change (bundled):** add `EntityDeletedEvent` + dispatch from `BaseRepository::delete()` —
   [Bundled core change](#bundled-core-change-entitydeletedevent). Makes create/update/delete auditable.
2. **Aegis change (bundled, optional integration):** add RBAC semantic domain events + dispatch from
   Aegis's semantic methods — [Bundled Aegis change](#bundled-aegis-change-rbac-domain-events).
3. `audit_logs` table (migration) + indexes.
4. `AuditSubscriber` (core/auth/entity events incl. `EntityDeletedEvent`) + `AegisAuditSubscriber`
   (RBAC domain events, registered only when Aegis is present); `AuditRecorder` writes normalized rows.
5. `GET /audit-logs` (→ `/v1/audit-logs`) — filterable, paginated, `audit.view`-gated, typed response.
6. `audit.view` permission (declared via `permissions()`).
7. `config/audit.php` — kill-switch, table allow/deny, capture toggles, redaction, retention.
8. Sensitive-field redaction in `changes`/`context`, including an auth-event token allow-list (no token
   values ever serialized — see [Three safeguards](#three-load-bearing-safeguards)).
9. A retention prune **console command** + config.

**Out of scope (later):**
- **Other extensions' domain events.** Audit's seam is "subscribe to whatever semantic events a producer
  emits." Beyond core + Aegis, other extensions (content workflow, billing, …) emitting their own
  auditable events is a later, additive concern — each producer ships its events; audit maps them.
- **Operations that bypass `BaseRepository` / emit no event** (raw query writes) — invisible to
  event-sourcing. Documented limitation, not a bug.
- Export (CSV), tamper-evident hash-chaining, a write-time `audit()` facade, UI (the Lemma page is a
  separate consumer spec).

## The normalized row (`audit_logs`)

One shape, every source fills it — that's what makes it queryable.

| Column | Type | Notes |
|---|---|---|
| `id` | bigint PK autoincrement | |
| `uuid` | string(12) unique | NanoID |
| `occurred_at` | timestamp(idx) | event time (`BaseEvent::getTimestamp()`) |
| `actor_uuid` | string(12) nullable, idx | who (null = system/anonymous) |
| `actor_label` | string nullable | cached display (email/username) — row is self-describing |
| `action` | string(32) idx | verb: `created` `updated` `deleted` `login` `login_failed` `logout` `security_violation` `rate_limit_exceeded` |
| `category` | string(24) idx | `auth` `rbac` `user` `content` `security` `data` |
| `target_type` | string(64) | entity/table: `user` `role` `permission` `content_entry` `session` … |
| `target_uuid` | string(64) nullable | which |
| `target_label` | string nullable | cached (name/title/email/slug) |
| `changes` | json nullable | `{field: {from, to}}` for updates; null otherwise; **redacted** |
| `context` | json nullable | `{ip, user_agent, request_id, session_uuid, event_id}` |
| `created_at` | timestamp | insert time (≈ occurred_at) |

**Indexes:** `(occurred_at)`, `(actor_uuid, occurred_at)`, `(target_type, target_uuid, occurred_at)`,
`(category, occurred_at)`. These serve the three real queries: global feed, "everything actor X did",
and "history of this target". **No foreign keys** — `actor_uuid`/`target_uuid` are soft references
(actors/targets live in other packages), mirroring how `auth_sessions` indexes `user_uuid` without an
FK.

Migration: `migrations/001_CreateAuditLogsTable.php` implementing `MigrationInterface`
(`up`/`down`/`getDescription`), registered via classmap + `loadMigrationsFrom(..., MigrationPriority::DEFAULT, 'glueful/audit')`.

## Event sourcing — `AuditSubscriber`

Implements `Glueful\Events\EventSubscriberInterface`; subscribed in `boot()` via
`$eventService->subscribe(AuditSubscriber::class)`.

```php
public static function getSubscribedEvents(): array {
    return [
        EntityCreatedEvent::class        => 'onEntityCreated',   // Glueful\Events\Database
        EntityUpdatedEvent::class        => 'onEntityUpdated',
        EntityDeletedEvent::class        => 'onEntityDeleted',   // bundled core addition
        AuthenticationFailedEvent::class => 'onAuthFailed',      // Glueful\Events\Auth
        SessionCreatedEvent::class       => 'onSessionCreated',
        SessionDestroyedEvent::class     => 'onSessionDestroyed',
        RateLimitExceededEvent::class    => 'onRateLimitExceeded',
        AdminSecurityViolationEvent::class => 'onSecurityViolation', // Glueful\Events\Security
    ];
}
```

**Mapping (per handler):**

| Event | action | category | target_type / uuid / label | changes |
|---|---|---|---|---|
| `EntityCreatedEvent` | `created` | derived from table | table-mapped / `getEntityId()` / best-effort label | — |
| `EntityUpdatedEvent` | `updated` | derived from table | same | `getChanges()` → `{from,to}` (redacted) |
| `EntityDeletedEvent` | `deleted` | derived from table | table-mapped / id from pre-delete record / label from pre-delete record | `null` (see below) |
| `AuthenticationFailedEvent` | `login_failed` | `auth` | `user` / — / `getUsername()` | `{reason}` |
| `SessionCreatedEvent` | `login` | `auth` | `user` / `getUserUuid()` / `getUsername()` | — |
| `SessionDestroyedEvent` | `logout` | `auth` | `user` / `getUserUuid()` / — | `{reason}` (`getReason()`) |
| `RateLimitExceededEvent` | `rate_limit_exceeded` | `security` | `rate_limit` / — / `getRule()` | `{count, limit}` |
| `AdminSecurityViolationEvent` | `security_violation` | `security` | from `$violationType` / `$userUuid` | `{message}` |

**Category derivation from table** (config-mapped, with defaults): `users`/`profiles` → `user`;
`roles`/`permissions`/`user_roles`/`user_permissions` → `rbac`; `content_*`/`entries` → `content`;
else → `data`.

**Target label** (best-effort, from the entity payload): first present of
`name` → `title` → `display_title` → `email` → `username` → `slug`.

**Delete row shape.** For `deleted`, `changes` is **`null`** — we record *that* it was deleted, not a
full copy of the row. `target_uuid`/`target_label` are derived from the event's pre-delete record
(`$originalData`). We deliberately do **not** store the whole deleted record: a full snapshot raises
retention/privacy risk and bloats the table. (If a specific table later needs a recoverable snapshot,
that's an opt-in, redacted, per-table feature — not the default.)

### Three load-bearing safeguards

1. **Recursion guard (mandatory).** The recorder writes via a **raw insert through the
   `Connection`/query builder — NOT `BaseRepository::create()`** (which itself dispatches
   `EntityCreatedEvent`). Additionally the subscriber hard-skips the `audit_logs` table. Without this,
   each audit write would audit itself. This is the single most important implementation rule.
2. **Table allow/deny filtering — with *conditional* RBAC-pivot suppression.** Entity events fire for
   *every* `BaseRepository::create/update/delete` — including noise (`auth_sessions`, `cache`,
   `activity_logs`, refresh tokens). `config/audit.php` statically denies those + `audit_logs` itself.
   For the RBAC pivots, the picture is uneven (verified in Aegis):
   - `role_permissions` (`RolePermissionRepository`) **does** fire generic entity events (it uses
     `BaseRepository::create`). It's suppressed from generic capture **only when the Aegis semantic
     subscriber is active** (avoiding a duplicate row); when inactive, it **falls back** to the generic
     row rather than being dropped.
   - `user_roles` / `user_permissions` (`UserRoleRepository` / `UserPermissionRepository`) **override
     `create()` with a raw insert and fire NO entity event.** So there's nothing to double-record and
     **no generic fallback exists** — when the Aegis subscriber is inactive (old/no Aegis, or
     `capture.rbac=false`) these grants are **unaudited** (the same "bypass writes" limitation). The
     pinned bundled-Aegis path always ships the semantic events, so the normal path covers them fully;
     this gap is only the degraded mode.

   The provider computes `rbac_semantic_active` at boot (exposed as config `audit.rbac_semantic_active`);
   the generic subscriber suppresses the `rbac_pivot_tables` only when it's true. Role/permission
   *entity* CRUD (`roles`/`permissions`) is always generic (reads fine: "created role Admin").
3. **Redaction + auth-event token allow-list.** `changes`/`context` must never store secret values
   (password hashes, tokens, keys). Two layers:
   - *Generic entity rows:* reuse the framework's unified sensitive-parameter redaction; redact by
     field-name pattern (`password`, `*_token`, `secret`, `api_key`, …) → values become `"[redacted]"`.
   - *Auth handlers (non-negotiable):* `SessionCreatedEvent::getTokens()` and
     `SessionDestroyedEvent::getAccessToken()` expose live tokens. The auth handlers must build their
     rows from an **explicit safe allow-list of fields** (`user_uuid`, `username`, `reason`, `ip`,
     `user_agent`, `event_id`) and **never** call the token accessors or serialize the event wholesale.
     No access/refresh token value may appear anywhere in `changes` or `context`.

### RBAC domain events — `AegisAuditSubscriber` (optional)

A **second** subscriber handles Aegis's semantic RBAC events, kept separate so audit never
hard-depends on Aegis. It's registered in `boot()` **only when Aegis is present** (detected via
`class_exists(\Glueful\Extensions\Aegis\Events\RoleAssignedEvent::class)`); if Aegis isn't installed,
it's simply never registered and the rest of audit works unchanged. (Referencing `Event::class` is a
compile-time string — no autoload — and the typed handler only loads when an event actually fires, so
this is safe with Aegis as a soft dependency.)

| Aegis event | action | target_type / uuid | context / changes |
|---|---|---|---|
| `RoleAssignedEvent` | `role_assigned` | `user` / principal uuid | role uuid + slug/name, resource filter, expiry, constraints, actor |
| `RoleRevokedEvent` | `role_revoked` | `user` / principal uuid | role uuid + slug/name, actor |
| `PermissionAssignedEvent` | `permission_assigned` | `user` / principal uuid | permission uuid + slug, resource filter, expiry, actor |
| `PermissionRevokedEvent` | `permission_revoked` | `user` / principal uuid | permission uuid + slug, actor |
| `RolePermissionAssignedEvent` | `role_permission_assigned` | `role` / role uuid | permission uuid + slug, actor |
| `RolePermissionRevokedEvent` | `role_permission_revoked` | `role` / role uuid | permission uuid + slug, actor |

All are `category: rbac`. **Target = the entity being modified**: for grants *to a user* the target is
the **user** (so "everything that happened to Jane" finds her role/permission changes); for
role↔permission links the target is the **role** (so a role's permission history is one filter). The
*other* side (the role/permission uuid+slug) lives in `context`/`changes`, JSON-searchable. `actor`,
`ip`, etc. resolve the same way as for entity events.

### Actor resolution

Entity events don't carry the actor. The subscriber resolves it from the **current request context**
(`Glueful\Http\RequestUserContext` / the authenticated principal) at event time → `actor_uuid` +
`actor_label`. Auth events carry their own subject. CLI/system writes → `actor_uuid = null`,
`actor_label = 'system'`. Context (`ip`, `user_agent`, `request_id`) also comes from the request.

## Bundled core change — `EntityDeletedEvent`

This MVP includes a small, isolated **framework** change (in `glueful/framework`, not this repo) so
deletes are auditable from day one — create/update/delete is the basic CRUD triplet an audit log is
expected to answer.

- **Add** `Glueful\Events\Database\EntityDeletedEvent extends BaseEvent`, mirroring
  `EntityCreatedEvent`/`EntityUpdatedEvent`:
  - Constructor: `__construct(array|object $originalData, string $table, array $metadata = [])` — where
    `$originalData` is the **pre-delete** record (so the subscriber can derive `target_uuid`/`target_label`).
  - Accessors: `getEntity()`/`getOriginalData()`, `getTable()`, `getEntityId()`, `getMetadata()`.
  - Metadata parity with create/update: `entity_id`, `primary_key`, `affected_rows`, `operation: 'delete'`.
- **Dispatch** it from `BaseRepository::delete()` **after a successful delete** (rows affected > 0),
  with the record that was read prior to deletion.
- It carries the same cache-tag/`isUserRelated` conveniences as its siblings if those are trivial to mirror.
- This is the **only** core change; everything else is the extension subscribing.

Versioning: pin `extra.glueful.requires.glueful` to the framework version that ships `EntityDeletedEvent`
(release the framework first, then pin — per the release-before-dependents rule).

## Bundled Aegis change — RBAC domain events

A change in **`glueful/aegis`** (not this repo) so RBAC actions are auditable *semantically*, not as
pivot-table noise. This is the integration **seam**, and it's a one-way, optional coupling: Aegis emits
events; audit subscribes if present. **Audit does not require Aegis, and Aegis does not require audit.**

- **Add six PSR-14 domain events** under `Glueful\Extensions\Aegis\Events\` (extending the framework
  `BaseEvent`), each carrying the actors and identifiers an audit row needs (actor uuid, principal/role
  uuid, role/permission uuid + slug/name, resource filter, expiry, constraints):
  - `RoleAssignedEvent`, `RoleRevokedEvent` (user ↔ role)
  - `PermissionAssignedEvent`, `PermissionRevokedEvent` (direct user ↔ permission grant)
  - `RolePermissionAssignedEvent`, `RolePermissionRevokedEvent` (role ↔ permission)
- **Keep `AuditService` as-is** if its channel logging still has operational value — it's orthogonal.
  The **domain events are the new integration seam**; `AuditService` is not. **Do not scrape the
  `rbac_audit` log channel.**
- These events are generically useful (notifications, cache invalidation, webhooks), not audit-specific
  — which is why they belong in Aegis, not audit.

### Dispatch owner — one pivot write → one event (exactly-once)

Aegis has many entry points (controllers, `AegisPermissionProvider`, `RoleService`,
`PermissionAssignmentService`, `BootstrapAdminService`, and our app's `UserAdminController`). Dispatching
in a *service* layer would miss callers that bypass it (e.g. `AegisPermissionProvider::assignRole` calls
the repo directly, not `RoleService`). The single point **all** paths converge on is the **pivot
repository**. So the dispatch owner per family is the repository method that performs the write:

*(Method names verified against Aegis as of this spec.)*

| Family | Dispatch owner (method) | Event |
|---|---|---|
| user ↔ role | `UserRoleRepository::assignRole` (callers — provider, `RoleService` — all route here) | `RoleAssignedEvent` |
| | `UserRoleRepository::revokeRole` / `revokeAllUserRoles` | `RoleRevokedEvent` (one per row removed) |
| user ↔ permission | `UserPermissionRepository::create` (the insert chokepoint that `createUserPermission`, `AegisPermissionProvider::assignPermission`, and `PermissionAssignmentService` all converge on) | `PermissionAssignedEvent` |
| | `UserPermissionRepository::revokeUserPermission` / `revokeAllUserPermissions` | `PermissionRevokedEvent` (per row) |
| role ↔ permission | `RolePermissionRepository::assignPermissionToRole` / `batchAssignPermissions` | `RolePermissionAssignedEvent` (per permission) |
| | `RolePermissionRepository::revokePermissionFromRole` / `batchRevokePermissions` | `RolePermissionRevokedEvent` (per permission) |

Rules that make this deterministic:
- **Dispatch only on an actual mutation** — skip no-ops. `UserRoleRepository::assignRole` and
  `RolePermissionRepository::assignPermissionToRole` already early-return the existing row when the grant
  exists → **no event**; a revoke that affected 0 rows → no event. Mirrors `EntityDeletedEvent`'s
  "affected > 0" rule.
- *(If pinning user-permission dispatch to the generic-named `create()` is undesirable, the alternative
  is to add a named `assignUserPermission()` chokepoint and route the provider + service through it.
  Either is fine; the plan picks one and proves single-dispatch.)*
- **Batch/replace dispatch one event per affected item**, not one per call — so the "replace/sync" path
  (`PUT /rbac/roles/{uuid}/permissions`) naturally yields an assign/revoke event per delta because it
  routes through these same repo methods.
- The event payload carries the **uuids + the write `options`** (resource filter, expiry, constraints);
  the audit subscriber enriches `slug`/`name` labels and resolves the actor from the request context
  (a `BootstrapAdminService` write → `actor = system`).

> **The implementation plan must, before coding:** (1) trace the call graph and *prove* every path
> (controller, provider, service, batch, replace, bootstrap, app `UserAdminController`) writes the pivot
> tables **only** through these repo methods — if any path issues a raw pivot write, route it through the
> repo or add a dispatch there; and (2) ship a test per entry point asserting **exactly one** event per
> semantic action (no duplicates, no misses).

Versioning: release Aegis with the events first, then audit pins a soft/`suggest` dependency on that
Aegis version (audit keeps `requires.extensions: []` — Aegis stays optional).

## Write path — `AuditRecorder`

A small service (shared, autowired) with the one method the subscriber calls:

```php
public function record(AuditEntry $entry): void
```

- Builds the row, redacts, and **raw-inserts** into `audit_logs` (generating a NanoID `uuid`).
- Best-effort & non-throwing: a failure to write an audit row must **never** break the audited
  operation — catch, log to the framework logger, move on.
- Synchronous by default; an optional `audit.async` config can defer to the queue later (out of MVP).

## Read API — `GET /audit-logs`

`routes/routes.php`, loaded via `loadRoutesFrom` (gated on `config('audit.routes_enabled', true)`):

```php
$router->group(['prefix' => '/audit-logs', 'middleware' => ['auth']], function (Router $router): void {
    $router->get('', [AuditLogController::class, 'index'])
        ->middleware('audit_permission:audit.view');
    $router->get('/{uuid}', [AuditLogController::class, 'show'])
        ->middleware('audit_permission:audit.view');
});
```

Resolves to `/v1/audit-logs` in Lemma (framework applies the API version prefix, same as aegis `/rbac/*`).

- **`index`** — filters from query: `actor`, `action`, `category`, `target_type`, `target_uuid`,
  `from`, `to` (ISO timestamps), `page`, `per_page`. Returns `Response::paginated(...)` (envelope:
  `data`, `current_page`, `per_page`, `total`, `total_pages`, …) — the same flat shape the SPA already
  consumes for `/rbac/*` and `/users`.
- **`show`** — single row by uuid, `Response::success` / `Response::notFound`.
- **No write routes** (append-only).
- **Typed response** `AuditLogData` DTO + `#[ApiOperation]`/`#[ApiResponse(200, collection: true,
  schema: AuditLogData::class)]` for OpenAPI, mirroring flags' controller docs.
- Reads via an `AuditLogRepository extends BaseRepository` (`getTableName(): 'audit_logs'`) using
  `paginate()` / `findRecordByUuid()` — reads are fine through BaseRepository (only *writes* must avoid
  it).

**Permission gating.** Declare the permission in the provider's `permissions()`:
`Permission::define('audit.view')->label('View audit log')->category('audit')`. Gate the routes with an
`audit_permission` `RouteMiddleware` (a thin mirror of flags' `RequireFlagsPermission`, checking
`audit.view` against the post-auth principal) — registered in `services()` and by middleware alias.
*(If a generic framework permission-gate middleware is preferred over a per-extension one, use that
instead; the contract is "require `audit.view`".)*

## Configuration — `config/audit.php`

**What "default-off" means here:** the *extension* is opt-in — you install + enable it (it ships
disabled in the registry, recording nothing until then). **Once enabled, it records by default** —
that's the point of enabling it. `AUDIT_ENABLED` is a separate runtime **kill-switch** that defaults
*on* while the extension is active (set it `false` to keep the extension installed but inert without
disabling it). So: opt-in to install/enable; records once enabled; `AUDIT_ENABLED=false` to pause.

```php
return [
    'enabled'        => env('AUDIT_ENABLED', true),     // runtime kill-switch (extension already opt-in)
    'routes_enabled' => env('AUDIT_ROUTES_ENABLED', true),
    'capture' => [
        'entities' => true,   // EntityCreated/Updated/Deleted
        'auth'     => true,   // login / login_failed / logout
        'security' => true,   // rate-limit / admin security violations
        'rbac'     => true,   // Aegis domain events (only effective when Aegis is installed)
    ],
    // Tables the GENERIC entity subscriber always ignores (deny-list).
    'ignore_tables'  => ['audit_logs', 'auth_sessions', 'refresh_tokens', 'activity_logs', 'cache', /*…*/],
    // RBAC assignment pivots — suppressed from generic capture ONLY when the Aegis semantic subscriber
    // is active (else recorded generically as a fallback, so RBAC is never silently dropped).
    'rbac_pivot_tables' => ['user_roles', 'user_permissions', 'role_permissions'],
    'category_map'   => [ /* table => category overrides */ ],
    'redact_fields'  => ['password', 'password_hash', 'secret', 'api_key', '*_token'],
    'retention_days' => env('AUDIT_RETENTION_DAYS', 365),
];
```

Merged in `register()` via `$this->mergeConfig('audit', require __DIR__.'/../config/audit.php')`.
Skeleton/app may shadow it (per the release config-parity practice).

## Retention

A console command `audit:prune` (auto-discovered from `src/Console`) that deletes rows older than
`audit.retention_days` (batched), modeled on `LogCleanupTask`/`DatabaseLogPruner`. The app schedules it
(daily) via its scheduler config — the extension ships the command, not the schedule.

## Extension wiring

**`composer.json`** (matches `glueful/flags`):
```json
{
  "name": "glueful/audit",
  "type": "glueful-extension",
  "require": { "php": "^8.3" },
  "suggest": {
    "glueful/aegis": "Enables rich RBAC audit rows (role/permission assigned/revoked). Optional."
  },
  "autoload": {
    "psr-4": { "Glueful\\Extensions\\Audit\\": "src/" },
    "classmap": ["migrations/"]
  },
  "extra": {
    "glueful": {
      "name": "Audit",
      "description": "Event-sourced audit trail for Glueful apps.",
      "version": "1.0.0",
      "categories": ["security", "operations"],
      "provider": "Glueful\\Extensions\\Audit\\AuditServiceProvider",
      "requires": { "glueful": ">=<pin-at-release>", "extensions": [] }
    }
  }
}
```
Note `glueful/aegis` is **`suggest`**, not `require`, and `requires.extensions` stays `[]` — Aegis is a
soft dependency. (Pin the suggested Aegis version once the events-bearing Aegis release exists.)

**`AuditServiceProvider extends Glueful\Extensions\ServiceProvider`:**
```php
public static function services(): array {
    return [
        AuditRecorder::class      => ['class' => AuditRecorder::class,      'shared' => true, 'autowire' => true],
        AuditSubscriber::class    => ['class' => AuditSubscriber::class,    'shared' => true, 'autowire' => true],
        AegisAuditSubscriber::class => ['class' => AegisAuditSubscriber::class, 'shared' => true, 'autowire' => true],
        AuditLogRepository::class => ['class' => AuditLogRepository::class, 'shared' => true, 'autowire' => true],
    ];
}
public function register(ApplicationContext $context): void {
    $this->mergeConfig('audit', require __DIR__ . '/../config/audit.php');
}
public function boot(ApplicationContext $context): void {
    $this->loadMigrationsFrom(__DIR__ . '/../migrations', MigrationPriority::DEFAULT, 'glueful/audit');
    if ((bool) config($context, 'audit.enabled', true)) {
        // Is RBAC captured semantically? (Aegis events present AND capture.rbac on.) The generic
        // subscriber reads this to decide pivot suppression vs. fallback; it gates the Aegis subscriber.
        $rbacSemantic = (bool) config($context, 'audit.capture.rbac', true)
            && class_exists(\Glueful\Extensions\Aegis\Events\RoleAssignedEvent::class);
        config($context, ['audit.rbac_semantic_active' => $rbacSemantic]); // exposed to the subscriber

        $events = app($context, EventService::class);
        $events->subscribe(AuditSubscriber::class);          // suppresses pivots iff rbac_semantic_active
        if ($rbacSemantic) {
            $events->subscribe(AegisAuditSubscriber::class); // semantic RBAC rows
        }
    }
    if ((bool) config($context, 'audit.routes_enabled', true)) {
        $this->loadRoutesFrom(__DIR__ . '/../routes/routes.php');
    }
    $this->discoverCommands('Glueful\\Extensions\\Audit\\Console', __DIR__ . '/Console');
}
public function permissions(): array {
    return [ Permission::define('audit.view')->label('View audit log')->category('audit') ];
}
```

## Gaps & follow-on work

1. **`EntityDeletedEvent`** — **bundled into this MVP** (no longer a gap).
2. **Aegis RBAC domain events** — **bundled into this MVP** (no longer a gap); RBAC reads semantically.
3. **Other producers.** The pattern is open-ended: any extension that emits semantic events (content
   workflow, billing, …) can be mapped to audit rows the same way Aegis is. Additive, per-producer,
   later.
4. **Bypass writes.** Any mutation issued via raw queries (not `BaseRepository`, and not emitting a
   domain event) is invisible to event-sourcing. Documented limitation; revisit per-subsystem if it matters.

## Decisions (resolved; flag to override)

1. **Separate `audit_logs` table**, not `activity_logs` — different shape, retention, immutability,
   access control.
2. **Event-sourced via subscribers** — no per-controller `audit()` calls.
3. **Append-only** — no write/update/delete API.
4. **Raw insert on the write path** (never `BaseRepository::create`) + skip `audit_logs` — the
   non-negotiable recursion guard.
5. **3-piece MVP: bundle `EntityDeletedEvent` (core) AND Aegis RBAC domain events.** Create/update/delete
   and *semantic* RBAC (role/permission assigned/revoked) are all readable from day one — shipping an
   audit trail that misses deletes, or renders RBAC as `created user_roles`, would fail the first and
   most security-sensitive things users ask of it.
6. **Aegis is a soft dependency.** `composer suggest` (not `require`), `requires.extensions: []`. The
   `AegisAuditSubscriber` is registered only when Aegis's event classes exist; absent Aegis, audit still
   records core/auth/entity events. Aegis emits the events; it does not depend on audit (one-way seam).
7. **Conditional pivot suppression; degraded — not silent — without semantic events.** Suppression is
   gated on `rbac_semantic_active`. Normal (bundled-Aegis) path: full semantic coverage. Degraded mode
   (old/no Aegis or `capture.rbac=false`): `role_permissions` falls back to a generic row;
   `user_roles`/`user_permissions` are unaudited (their repos raw-insert, no entity event to fall back
   to). The version pin keeps the normal path the default; the degraded gap is documented, not hidden.
   *(If we want fallback coverage for all three, the Aegis change can also route the two raw-insert
   repos through `BaseRepository::create/delete` — optional, called out in the plan.)*
8. **One pivot write → one event.** Aegis dispatches semantic events from the **pivot repositories**
   (the single chokepoint every entry point converges on), only on actual mutations (no-ops emit
   nothing), one per affected item for batch/replace — verified by per-entry-point exactly-once tests.
9. **Opt-in extension, records once enabled** — installed disabled in the registry; `AUDIT_ENABLED` is a
   runtime kill-switch defaulting *on* while enabled.
10. **Auth rows never carry tokens** — auth handlers use a field allow-list and never touch the token
   accessors (safeguard #3).

## Acceptance criteria

- [ ] `migrate:run` creates `audit_logs` with the columns + indexes above.
- [ ] A successful login writes one `login` row (actor + ip + session uuid); a failed login writes one `login_failed` row with the reason.
- [ ] Creating/updating a user (via BaseRepository) writes `created`/`updated` rows with actor resolved from the request and (for update) a redacted `changes` diff.
- [ ] **Deleting a user/role (via BaseRepository) writes one `action=deleted` row** with `target_uuid`/`target_label` from the pre-delete record and `changes = null` (no full snapshot). [requires the bundled `EntityDeletedEvent`]
- [ ] The audit write itself produces **no** further audit row (recursion guard verified); ignored tables produce none.
- [ ] `changes`/`context` never contain raw password/token values.
- [ ] **Login and logout audit rows contain no access- or refresh-token value anywhere in `changes` or `context`** (token allow-list verified).
- [ ] **With Aegis installed:** assigning a role writes one `action=role_assigned`, `category=rbac` row with `target_type=user`/principal uuid, the role uuid+slug in `context`, and the actor — and **no** duplicate generic `user_roles` row. Revoking writes `role_revoked`; role↔permission link writes `role_permission_assigned`/`_revoked` with `target_type=role`.
- [ ] **Exactly-once across entry points:** the same role assignment triggered via the controller, `AegisPermissionProvider`, a service, batch, the `PUT …/permissions` replace path, and `BootstrapAdminService` each produces **exactly one** semantic row (no duplicates, no misses); a no-op assign (already assigned) produces **none**.
- [ ] **With Aegis NOT installed (or `capture.rbac=false`):** the extension still boots and records core/auth/entity events; `AegisAuditSubscriber` isn't registered (no class-not-found). `role_permissions` writes fall back to generic rows; `user_roles`/`user_permissions` writes are not captured (documented degraded mode — those repos raw-insert).
- [ ] `GET /v1/audit-logs` returns paginated rows; `actor`, `action`, `category`, `target_type`, `target_uuid`, `from`, `to` filters all narrow the result; `audit.view` is required (403 without).
- [ ] `audit:prune` deletes rows older than the retention window.
- [ ] Disabling (`AUDIT_ENABLED=false`) stops recording; `routes_enabled=false` removes the endpoint.
- [ ] `composer test` + framework PHPStan/phpcs pass for the extension (and the bundled framework/Aegis changes pass their own CI).

## File map

```
extensions/audit/
├── composer.json
├── config/audit.php
├── migrations/001_CreateAuditLogsTable.php
├── routes/routes.php
├── src/
│   ├── AuditServiceProvider.php
│   ├── Events/AuditSubscriber.php         (core/auth/entity events)
│   ├── Events/AegisAuditSubscriber.php    (RBAC domain events; registered only if Aegis present)
│   ├── Services/AuditRecorder.php
│   ├── Support/AuditEntry.php            (value object the subscriber builds)
│   ├── Support/ActorResolver.php         (request-context → actor uuid/label/ip)
│   ├── Repositories/AuditLogRepository.php
│   ├── Http/Controllers/AuditLogController.php
│   ├── Http/Middleware/RequireAuditPermission.php
│   ├── Http/DTOs/AuditLogData.php        (typed response, OpenAPI)
│   └── Console/PruneAuditLogsCommand.php (#[AsCommand] audit:prune)
└── tests/

# Bundled change — framework (separate repo: glueful/framework)
framework/src/Events/Database/EntityDeletedEvent.php   (new)
framework/src/Repository/BaseRepository.php            (dispatch EntityDeletedEvent in delete())
+ framework tests

# Bundled change — Aegis (separate repo: glueful/aegis)
aegis/src/Events/{RoleAssigned,RoleRevoked,PermissionAssigned,PermissionRevoked,
                  RolePermissionAssigned,RolePermissionRevoked}Event.php   (new)
aegis/src/Repositories/UserRoleRepository.php        (dispatch on assignRole/revokeRole/revokeAllUserRoles)
aegis/src/Repositories/UserPermissionRepository.php  (dispatch on create/revokeUserPermission/revokeAllUserPermissions)
aegis/src/Repositories/RolePermissionRepository.php  (dispatch on assignPermissionToRole/revoke/batch*)
+ aegis tests: exactly-once per entry point (controller/provider/service/batch/replace/bootstrap)
```
