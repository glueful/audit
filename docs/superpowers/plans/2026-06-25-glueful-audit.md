# glueful/audit — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development (recommended)
> or superpowers:executing-plans to execute task-by-task. Steps use `- [ ]` checkboxes. This plan spans
> **three repos** and must be done in phase order (framework → aegis → audit) because each depends on the
> prior. Within a phase, tasks are mostly independent.

**Goal:** Ship an event-sourced, normalized, append-only audit trail as the `glueful/audit` extension,
with the two bundled producer changes (framework `EntityDeletedEvent`; Aegis RBAC domain events) so
create/update/delete and semantic RBAC are all readable from day one.

**Architecture:** Producers dispatch PSR-14 events; `glueful/audit` subscribes and writes normalized
rows via a raw insert (recursion-safe), exposed through `GET /v1/audit-logs`. See the design spec:
[`../specs/2026-06-25-glueful-audit-design.md`](../specs/2026-06-25-glueful-audit-design.md).

**Tech Stack:** PHP 8.3+, Glueful framework (PSR-14 events, `BaseRepository`, `SchemaBuilder`,
`Response`, `Permission::define`, `ServiceProvider`), PHPUnit 10, PHPStan, PHP_CodeSniffer (PSR-12).

**Repos (absolute paths):**
- framework: `/Users/michaeltawiahsowah/Sites/glueful/framework`
- aegis: `/Users/michaeltawiahsowah/Sites/glueful/extensions/aegis`
- audit: `/Users/michaeltawiahsowah/Sites/glueful/extensions/audit`

**Per-phase gate:** `composer test` + `composer analyse`/`phpstan` + `composer phpcs` (or the repo's CI
script) must pass in the repo being changed. **Do not commit until told** if a hold-commits instruction
is in effect; otherwise commit per task on `dev`.

**Cross-repo dev:** develop against local path/dev branches; the **release + version-pin ordering**
(framework → aegis → audit) is the final phase (Task 4.x), per the release-before-dependents rule.

---

## Phase 1 — Framework: `EntityDeletedEvent` (+ enable subclass dispatch)

**Verified facts** (file:line):
- `BaseRepository::delete()` (`framework/src/Repository/BaseRepository.php:304`) already reads the row
  first: `$originalData = $this->find($uuid);`, deletes, sets `$success = $affectedRows > 0`. The
  dispatch goes in the `if ($success) {}` block.
- Dispatch helper `BaseRepository::dispatchEvent()` (line ~326) is **private**:
  `app($this->context, EventService::class)->dispatch($event)` — best-effort (no-ops when `$context` is null).
- `EntityCreatedEvent` (`framework/src/Events/Database/EntityCreatedEvent.php`) is the mirror template.

### Task 1.1: `EntityDeletedEvent`

**Files:** Create `framework/src/Events/Database/EntityDeletedEvent.php`; Test
`framework/tests/Unit/Events/Database/EntityDeletedEventTest.php` (match the repo's test dir convention —
check an existing event test first).

- [ ] **Step 1 — failing test.** Assert the event exposes `getEntity()`, `getTable()`, `getEntityId()`
  (from `id`/`uuid`), `getOriginalData()`, and metadata round-trips.

```php
public function testExposesOriginalRecordAndId(): void
{
    $e = new EntityDeletedEvent(['uuid' => 'u1', 'name' => 'Jane'], 'users', ['operation' => 'delete']);
    self::assertSame('users', $e->getTable());
    self::assertSame('u1', $e->getEntityId());
    self::assertSame('Jane', $e->getEntity()['name']);
    self::assertSame('delete', $e->getMetadata('operation'));
}
```

- [ ] **Step 2 — run, expect fail** (class missing). `cd framework && ./vendor/bin/phpunit --filter EntityDeletedEvent`.

- [ ] **Step 3 — implement** (mirror `EntityCreatedEvent` exactly; add a `getOriginalData()` alias):

```php
<?php

declare(strict_types=1);

namespace Glueful\Events\Database;

use Glueful\Events\Contracts\BaseEvent;

/**
 * Entity Deleted Event
 *
 * Dispatched after an entity is deleted from the database (affected rows > 0).
 * Carries the PRE-DELETE record so consumers can derive identity/labels.
 */
class EntityDeletedEvent extends BaseEvent
{
    /**
     * @param array<string, mixed>|object $originalData The record as it was before deletion
     * @param string $table Database table name
     * @param array<string, mixed> $metadata Additional metadata
     */
    public function __construct(
        private readonly array|object $originalData,
        private readonly string $table,
        array $metadata = []
    ) {
        parent::__construct();
        foreach ($metadata as $key => $value) {
            $this->setMetadata($key, $value);
        }
    }

    /** @return array<string, mixed>|object */
    public function getEntity(): array|object
    {
        return $this->originalData;
    }

    /** @return array<string, mixed>|object */
    public function getOriginalData(): array|object
    {
        return $this->originalData;
    }

    public function getTable(): string
    {
        return $this->table;
    }

    public function getEntityId(): mixed
    {
        if (is_array($this->originalData)) {
            return $this->originalData['id'] ?? $this->originalData['uuid'] ?? null;
        }
        if (is_object($this->originalData)) {
            return $this->originalData->id ?? $this->originalData->uuid ?? null;
        }
        return null;
    }

    public function isUserRelated(): bool
    {
        return in_array($this->table, ['users', 'user_sessions', 'user_preferences'], true);
    }
}
```

- [ ] **Step 4 — run, expect pass.** Commit: `feat(events): add EntityDeletedEvent`.

### Task 1.2: Dispatch from `BaseRepository::delete()`

**Files:** Modify `framework/src/Repository/BaseRepository.php`; Test
`framework/tests/.../BaseRepositoryDeleteTest.php` (a repo subclass over a temp table, asserting the
event fires once with the pre-delete data on a real delete, and **not** when delete affects 0 rows).

- [ ] **Step 1 — failing test** using an in-suite test repo + a captured `EventService` (or a listener)
  to assert exactly one `EntityDeletedEvent` on a real delete, zero on a missing-uuid delete.
- [ ] **Step 2 — run, expect fail.**
- [ ] **Step 3 — implement.** In the existing `if ($success) {` block of `delete()`:

```php
if ($success) {
    $this->dispatchEvent(new EntityDeletedEvent($originalData, $this->table, [
        'entity_id' => $uuid,
        'timestamp' => time(),
        'primary_key' => $this->primaryKey,
        'affected_rows' => $affectedRows,
        'operation' => 'delete',
    ]));
}
```
Add `use Glueful\Events\Database\EntityDeletedEvent;` at the top.

- [ ] **Step 4 — run, expect pass.** Commit: `feat(repository): dispatch EntityDeletedEvent on delete`.

### Task 1.3: Make `dispatchEvent()` protected (enable subclass domain events)

Aegis repos (Phase 2) extend `BaseRepository` and must dispatch their own domain events through the same
best-effort path. `dispatchEvent()` is currently `private`.

- [ ] **Step 1** — change `private function dispatchEvent` → `protected function dispatchEvent` in
  `BaseRepository.php`. (No behavior change; widens visibility.)
- [ ] **Step 2 — verify** nothing else relies on it being private; run the full framework suite.
- [ ] **Step 3** — Commit: `refactor(repository): make dispatchEvent protected for subclass domain events`.

> **Phase-1 gate:** `composer ci` (framework) green. This phase is releasable on its own and adds value
> (deletes become evented) even before aegis/audit exist.

---

## Phase 2 — Aegis: RBAC domain events at the repository chokepoints

**Verified call graph** (every entry point converges on these repo methods):
- user↔role: `UserRoleRepository::assignRole` (no-op guard via `hasUserRole`), `revokeRole`,
  `revokeAllUserRoles`. (`UserRoleRepository` overrides `create()` raw — no entity event.)
- user↔permission: `UserPermissionRepository::create` (chokepoint for `createUserPermission`,
  `AegisPermissionProvider::assignPermission`, `PermissionAssignmentService`), `revokeUserPermission`,
  `revokeAllUserPermissions`. (Overrides `create()` raw — no entity event.)
- role↔permission: `RolePermissionRepository::assignPermissionToRole` (no-op guard),
  `revokePermissionFromRole`, `batchAssignPermissions`/`batchRevokePermissions` (loop the singles).

### Task 2.0: Give the pivot repos `ApplicationContext` (BLOCKER — do first)

`dispatchEvent()` no-ops when `$this->context` is null, and **Aegis currently constructs these repos
without context** — so provider- and bootstrap-triggered RBAC events would silently never fire. Verified
sites (must all be fixed):
- `AegisPermissionProvider` lazy getters — `new UserRoleRepository()` (line ~128),
  `new UserPermissionRepository()` (~139), `new RolePermissionRepository()` (~150). The provider already
  holds `private ApplicationContext $context` (line 40), so pass it: `new UserRoleRepository(null, $this->context)`, etc.
- `BootstrapAdminCommand` (line ~81) — `new RoleRepository()`, `new PermissionRepository()`,
  `new RolePermissionRepository()` passed into `BootstrapAdminService`. Resolve these from the container
  (which injects context) via `$this->getService(...)`, or construct with the command's `ApplicationContext`.
- **Grep the whole aegis repo** for `new UserRoleRepository(`, `new UserPermissionRepository(`,
  `new RolePermissionRepository(` and fix every direct construction to carry context (or come from DI).

- [ ] **Step 1 — failing test:** obtain each pivot repo the way production does (via the provider's
  getters and via the bootstrap command's wiring) and assert it dispatches a captured event when a write
  happens — i.e. its context is non-null. (Before the fix, this fails: no event.)
- [ ] **Step 2 — fix all construction sites** to pass context / resolve from DI.
- [ ] **Step 3 — pass.** Commit: `fix(rbac): construct pivot repositories with ApplicationContext`.

> Do NOT start Tasks 2.2–2.4 until 2.0 is green — without it the dispatch code is dead on those paths.

### Task 2.1: The six event classes

**Files:** Create under `extensions/aegis/src/Events/`:
`RoleAssignedEvent`, `RoleRevokedEvent`, `PermissionAssignedEvent`, `PermissionRevokedEvent`,
`RolePermissionAssignedEvent`, `RolePermissionRevokedEvent`. Test
`extensions/aegis/tests/.../EventsTest.php` (constructors + accessors).

- [ ] **Step 1 — failing test** for accessors on each.
- [ ] **Step 2 — run, expect fail.**
- [ ] **Step 3 — implement.** All extend `Glueful\Events\Contracts\BaseEvent`, call
  `parent::__construct()`, expose readonly getters. Example (the others follow the same shape):

```php
<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Events;

use Glueful\Events\Contracts\BaseEvent;

/** A role was assigned to a user (the user_roles pivot row was created). */
final class RoleAssignedEvent extends BaseEvent
{
    /** @param array<string,mixed> $options granted_by, expires_at, scope, … */
    public function __construct(
        public readonly string $userUuid,
        public readonly string $roleUuid,
        public readonly array $options = [],
    ) {
        parent::__construct();
    }
}
```

Shapes for the rest:
- `RoleRevokedEvent(string $userUuid, string $roleUuid)`
- `PermissionAssignedEvent(string $userUuid, string $permissionUuid, array $options = [])` — **no
  `resource` positional.** Aegis stores a scoped resource as JSON in `resource_filter`, not a `resource`
  column (verified: `AegisPermissionProvider::assignPermission` sets
  `$data['resource_filter'] = json_encode(['resource' => $resource])`). The event carries the **decoded
  `resource_filter`** (plus `granted_by`/`expires_at`) in `$options`; a `resource='*'` positional would
  silently lose scope.
- `PermissionRevokedEvent(string $userUuid, string $permissionUuid)`
- `RolePermissionAssignedEvent(string $roleUuid, string $permissionUuid, array $options = [])` (options
  carries the decoded `resource_filter`/`constraints` when present)
- `RolePermissionRevokedEvent(string $roleUuid, string $permissionUuid)`

- [ ] **Step 4 — pass.** Commit: `feat(events): add RBAC domain events`.

### Task 2.2: Dispatch from `UserRoleRepository`

**Files:** Modify `extensions/aegis/src/Repositories/UserRoleRepository.php`; Test
`extensions/aegis/tests/.../UserRoleRepositoryEventsTest.php`.

- [ ] **Step 1 — failing tests:** assign emits exactly one `RoleAssignedEvent`; a **second** assign of
  the same pair (no-op guard hits) emits **none**; `revokeRole` that deletes emits one `RoleRevokedEvent`,
  a revoke of a non-existent pair emits none; `revokeAllUserRoles` emits one per row removed.
- [ ] **Step 2 — run, expect fail.**
- [ ] **Step 3 — implement.** Dispatch only on real mutation:
  - In `assignRole()`: the no-op guard already early-returns the existing row before insert. Dispatch
    **after** `createUserRole($data)` succeeds:
    ```php
    $userRole = $this->createUserRole($data);
    if ($userRole !== null) {
        $this->dispatchEvent(new RoleAssignedEvent($userUuid, $roleUuid, $options));
    }
    return $userRole;
    ```
  - In `revokeRole()`: capture affected rows and dispatch once if > 0:
    ```php
    $deleted = (bool) $this->db->table($this->table)->where([
        'user_uuid' => $userUuid, 'role_uuid' => $roleUuid,
    ])->delete();
    if ($deleted) {
        $this->dispatchEvent(new RoleRevokedEvent($userUuid, $roleUuid));
    }
    return $deleted;
    ```
  - In `revokeAllUserRoles()`: read the role uuids first, delete, then dispatch one `RoleRevokedEvent`
    per removed pair (so the audit feed lists each). (If reading-first is too costly, dispatch a single
    revoke-all event — but the spec wants per-row; prefer the read-then-emit form.)
  Add `use Glueful\Extensions\Aegis\Events\{RoleAssignedEvent, RoleRevokedEvent};`.
- [ ] **Step 4 — pass.** Commit: `feat(rbac): emit role assigned/revoked events`.

### Task 2.3: Dispatch from `UserPermissionRepository`

**Files:** Modify `extensions/aegis/src/Repositories/UserPermissionRepository.php`; Test similarly.

- [ ] **Step 1 — failing tests:** a grant via `create()` emits one `PermissionAssignedEvent`; a **scoped**
  grant (`resource_filter` set) carries the decoded filter in the event (assert it is **not** `'*'` and
  not lost); `revokeUserPermission`/`revokeAllUserPermissions` emit `PermissionRevokedEvent`(s) only when
  rows go.
- [ ] **Step 2 — fail.**
- [ ] **Step 3 — implement.** In the **overridden** `create()`, after the successful insert — decode
  `resource_filter` (it's stored as JSON, there is no `resource` key):
  ```php
  $rf = isset($data['resource_filter']) && is_string($data['resource_filter'])
      ? json_decode($data['resource_filter'], true) : null;
  $this->dispatchEvent(new PermissionAssignedEvent(
      (string) ($data['user_uuid'] ?? ''),
      (string) ($data['permission_uuid'] ?? ''),
      array_filter([
          'resource_filter' => $rf,
          'granted_by' => $data['granted_by'] ?? null,
          'expires_at' => $data['expires_at'] ?? null,
      ], static fn ($v) => $v !== null),
  ));
  ```
  In `revokeUserPermission()`/`revokeAllUserPermissions()`: dispatch per removed row (read-then-delete or
  affected-count) as in 2.2.
- [ ] **Step 4 — pass.** Commit: `feat(rbac): emit user-permission assigned/revoked events`.

### Task 2.4: Dispatch from `RolePermissionRepository`

**Files:** Modify `extensions/aegis/src/Repositories/RolePermissionRepository.php`; Test similarly.

- [ ] **Step 1 — failing tests:** `assignPermissionToRole` emits one `RolePermissionAssignedEvent`
  (none when the "already assigned" guard hits); `revokePermissionFromRole` emits one per assignment
  deleted; `batchAssignPermissions`/`batchRevokePermissions` emit one per affected item (they loop the
  singles — assert the count); **`replaceRolePermissions` emits a `RolePermissionRevokedEvent` for each
  removed link AND a `RolePermissionAssignedEvent` for each added link** (this is the bug-catch test).
  > **Test-writing caveat:** `revokePermissionFromRole()` returns `true` even when the row is already
  > absent (no-op), so `batchRevokePermissions()`'s `success` tally can exceed rows actually deleted.
  > Assert the **emitted event count against rows actually deleted** (the dispatch is guarded by
  > `if ($this->delete(...))`) — **never** infer it from the batch success count. Include a test that
  > revoking an **already-absent** link emits **zero** events even though batch `success` is non-zero.
- [ ] **Step 2 — fail.**
- [ ] **Step 3 — implement.** In `assignPermissionToRole()`, after `$this->create($data)` succeeds and
  the record is retrieved (the early-return on existing already prevents a no-op event):
  ```php
  $this->dispatchEvent(new RolePermissionAssignedEvent($roleUuid, $permissionUuid, $options));
  ```
  In `revokePermissionFromRole()`, the loop deletes each assignment — dispatch once per actual delete:
  ```php
  foreach ($assignments as $assignment) {
      if ($this->delete($assignment['uuid'])) {
          $this->dispatchEvent(new RolePermissionRevokedEvent($roleUuid, $permissionUuid));
      }
  }
  ```
  **Fix `replaceRolePermissions()` (line ~266):** it currently removes existing links with a **raw
  `$this->delete($assignment->getUuid())` loop that bypasses `revokePermissionFromRole`** — so removed
  links emit **no** semantic event (and the generic `EntityDeletedEvent` is suppressed when semantic
  capture is on, so the removal is lost entirely). Route removals through the semantic method so each
  emits `RolePermissionRevokedEvent`:
  ```php
  foreach ($existing as $assignment) {
      $this->revokePermissionFromRole($roleUuid, $assignment->getPermissionUuid());
  }
  ```
  Adds come via `batchAssignPermissions` (already dispatches). Batch methods themselves need no extra dispatch.
- [ ] **Step 4 — pass.** Commit: `feat(rbac): emit role-permission assigned/revoked events`.

### Task 2.5: Exactly-once across entry points (integration)

**Files:** Test `extensions/aegis/tests/.../RbacEventDispatchAcrossEntryPointsTest.php`.

- [ ] For each family, drive the operation through **every** entry point and assert **exactly one**
  event per semantic action (no dup, no miss): controller, `AegisPermissionProvider`, the service,
  the batch path, the role-permission **replace/sync** path, and `BootstrapAdminService`.
- [ ] Assert the no-op cases (re-assign existing, revoke-absent) emit **zero**.
- [ ] Commit: `test(rbac): exactly-once event dispatch across entry points`.

> **Phase-2 gate:** aegis `composer test`/`analyse`/`phpcs` green. Releasable on its own (the events are
> generically useful; nothing breaks if no one subscribes).

---

## Phase 3 — The `glueful/audit` extension

Work in `/Users/michaeltawiahsowah/Sites/glueful/extensions/audit` (currently only README + .gitignore).

### Task 3.1: Scaffold — composer.json + ServiceProvider + config + phpunit

**Files:** `composer.json`, `phpunit.xml`, `src/AuditServiceProvider.php`, `config/audit.php`,
`tests/bootstrap.php` (+ a base `tests/Support/AuditTestCase.php` if a DB harness is needed — model on
flags' `tests/Support`).

- [ ] **composer.json** (mirror flags; Aegis is `suggest`, not `require`):
```json
{
  "name": "glueful/audit",
  "description": "Event-sourced audit trail for Glueful apps.",
  "type": "glueful-extension",
  "license": "MIT",
  "minimum-stability": "stable",
  "prefer-stable": true,
  "require": { "php": "^8.3" },
  "suggest": { "glueful/aegis": "Rich RBAC audit rows (role/permission assigned/revoked). Optional." },
  "require-dev": {
    "glueful/framework": "^<framework-with-EntityDeletedEvent>",
    "glueful/aegis": "^<aegis-with-events>",
    "phpunit/phpunit": "^10.5",
    "phpstan/phpstan": "^1.0",
    "squizlabs/php_codesniffer": "^3.6"
  },
  "autoload": { "psr-4": { "Glueful\\Extensions\\Audit\\": "src/" }, "classmap": ["migrations/"] },
  "autoload-dev": { "psr-4": { "Glueful\\Extensions\\Audit\\Tests\\": "tests/" } },
  "scripts": {
    "test": "vendor/bin/phpunit",
    "analyze": "vendor/bin/phpstan analyse",
    "phpcs": "vendor/bin/phpcs --standard=PSR12 src",
    "phpcbf": "vendor/bin/phpcbf --standard=PSR12 src"
  },
  "extra": { "glueful": {
    "name": "Audit", "displayName": "Audit",
    "description": "Event-sourced audit trail for Glueful apps.",
    "version": "1.0.0", "categories": ["security", "operations"],
    "publisher": "glueful-team",
    "provider": "Glueful\\Extensions\\Audit\\AuditServiceProvider",
    "requires": { "glueful": ">=<pin>", "extensions": [] }
  } }
}
```
(`glueful/aegis` is dev-only + suggest; **never** in `extra.glueful.requires.extensions`.)

- [ ] **`AuditServiceProvider`** — `services()`, `register()` (mergeConfig), `boot()`, `permissions()`.
  Use the flags `self::autowired(...)` helper pattern. `boot()` is the **exact** wiring from the spec
  (compute `rbac_semantic_active`, subscribe `AuditSubscriber`, conditionally subscribe
  `AegisAuditSubscriber`, load routes/migrations/commands). `permissions()` returns
  `Permission::define('audit.view')->label('View audit log')->category('Audit')->resource('audit')->managedBy('glueful/audit')`.
- [ ] **`config/audit.php`** — the spec's config (kill-switch, `capture.*`, `ignore_tables`,
  `rbac_pivot_tables`, `redact_fields`, `retention_days`).
- [ ] Commit: `chore: scaffold audit extension`.

### Task 3.2: Migration — `audit_logs`

**Files:** `migrations/001_CreateAuditLogsTable.php`; Test `tests/.../MigrationTest.php` (or assert via a
DB harness that the table + indexes exist).

- [ ] Implement `MigrationInterface` (mirror flags' migration). Columns + indexes from the spec:
```php
$schema->createTable('audit_logs', function ($table): void {
    $table->bigInteger('id')->primary()->autoIncrement();
    $table->string('uuid', 12);
    $table->timestamp('occurred_at');
    $table->string('actor_uuid', 12)->nullable();
    $table->string('actor_label', 255)->nullable();
    $table->string('action', 32);
    $table->string('category', 24);
    $table->string('target_type', 64)->nullable();
    $table->string('target_uuid', 64)->nullable();
    $table->string('target_label', 255)->nullable();
    $table->json('changes')->nullable();
    $table->json('context')->nullable();
    $table->timestamp('created_at')->nullable();
    $table->unique('uuid');
    $table->index('occurred_at');
    $table->index(['actor_uuid', 'occurred_at'], 'idx_audit_actor');
    $table->index(['target_type', 'target_uuid', 'occurred_at'], 'idx_audit_target');
    $table->index(['category', 'occurred_at'], 'idx_audit_category');
});
```
- [ ] Commit: `feat: audit_logs migration`.

### Task 3.3: Write path — `AuditEntry` VO, `ActorResolver`, `AuditRecorder`

**Files:** `src/Support/AuditEntry.php`, `src/Support/ActorResolver.php`, `src/Services/AuditRecorder.php`;
Tests for each.

- [ ] **`AuditEntry`** — immutable VO holding the normalized fields (occurred_at, actor_uuid/label,
  action, category, target_type/uuid/label, changes[], context[]).
- [ ] **`ActorResolver`** — given the request context (`Glueful\Http\RequestUserContext` / the post-auth
  principal), returns `[actor_uuid, actor_label, ip, user_agent, request_id]`; CLI/system → `[null,
  'system', …]`. (Confirm the exact request-context accessor against the framework; mirror how
  `RequireFlagsPermission` reads `auth.user`.)
- [ ] **`AuditRecorder::record(AuditEntry $entry): void`** — **TDD the two safeguards:**
  - **Test:** redaction — an entry whose `changes`/`context` contain `password`/`*_token`/`secret` keys
    is stored with those values replaced by `"[redacted]"`. Reuse the framework's unified
    sensitive-parameter redaction (confirm the class/helper name; else implement the field-pattern match
    from `config('audit.redact_fields')`).
  - **Test:** the write uses a **raw insert** (`$connection->table('audit_logs')->insert([...])` with a
    generated NanoID) and **never** `BaseRepository::create` — so it dispatches no event. Assert that
    recording does not itself trigger another audit (no recursion).
  - Non-throwing: wrap in try/catch, log to the framework logger on failure, never rethrow.
- [ ] Commit: `feat: audit recorder + redaction + actor resolver`.

### Task 3.4: Read store — `AuditLogRepository`

**Files:** `src/Repositories/AuditLogRepository.php` (`extends BaseRepository`, `getTableName(): 'audit_logs'`,
`$hasUpdatedAt = false`); a `paginateFiltered(array $filters, int $page, int $perPage): array` that
applies `actor`/`action`/`category`/`target_type`/`target_uuid`/`from`/`to` and returns the
`paginate()`-shaped envelope. Reads through BaseRepository are fine. Test the filter SQL.
- [ ] Commit: `feat: audit log repository (filtered pagination)`.

### Task 3.5: `AuditSubscriber` — core/auth/entity events (+ conditional pivot suppression)

**Files:** `src/Events/AuditSubscriber.php`; Tests.

- [ ] **`getSubscribedEvents()`** → `EntityCreatedEvent`/`EntityUpdatedEvent`/`EntityDeletedEvent` (Database),
  `AuthenticationFailedEvent`/`SessionCreatedEvent`/`SessionDestroyedEvent`/`RateLimitExceededEvent` (Auth),
  `AdminSecurityViolationEvent` (Security) — exactly the spec's mapping table.
- [ ] **Handlers** build an `AuditEntry` and call `AuditRecorder::record()`. Map action/category/target
  per the spec. **Auth handlers use the field allow-list** (`user_uuid`, `username`, `reason`, `ip`,
  `user_agent`, `event_id`) and **never** call `getTokens()`/`getAccessToken()`.
- [ ] **Conditional pivot suppression:** the entity handlers skip a table when it's in
  `config('audit.ignore_tables')`, OR it's `audit_logs`, OR (it's in `config('audit.rbac_pivot_tables')`
  AND `config('audit.rbac_semantic_active')` is true). Inject/read these via config.
- [ ] **Tests (TDD):**
  - login → one `login` row, **no token** anywhere (assert the serialized row contains neither the
    access nor refresh token string); failed login → one `login_failed` with reason.
  - `EntityCreated/Updated/Deleted` on `users` → `created`/`updated`/`deleted` rows; update carries a
    redacted `changes` diff; delete has `changes = null` and label from the pre-delete record.
  - ignored table → no row; `audit_logs` write → no row (recursion guard).
  - `role_permissions` create with `rbac_semantic_active = true` → **suppressed** (no generic row);
    with `false` → **one generic row** (fallback).
- [ ] Commit: `feat: core audit subscriber`.

### Task 3.6: `AegisAuditSubscriber` — RBAC domain events

**Files:** `src/Events/AegisAuditSubscriber.php`; Tests.

- [ ] **`getSubscribedEvents()`** → the six Aegis events (reference by `::class` — compile-time string,
  autoload-safe). Map each to its normalized row per the spec (actions `role_assigned`/`role_revoked`/
  `permission_assigned`/`permission_revoked`/`role_permission_assigned`/`role_permission_revoked`,
  `category: rbac`, target = affected user for grants-to-user / role for role↔permission links; the other
  uuid + looked-up slug/name in `context`).
- [ ] **Label enrichment:** look up role/permission slug+name from uuid (via the aegis read repos or a
  cache) to fill `target_label`/`context`. Best-effort; missing lookup → omit label, keep uuid.
- [ ] **Tests:** each event → exactly one correctly-shaped row; `role_assigned` row has `target_type=user`,
  the role uuid+slug in context, actor resolved; no duplicate generic `user_roles` row when suppression active.
- [ ] Commit: `feat: aegis RBAC audit subscriber`.

### Task 3.7: Read API — controller, DTO, middleware, routes

**Files:** `src/Http/Controllers/AuditLogController.php`, `src/Http/DTOs/AuditLogData.php`,
`src/Http/Middleware/RequireAuditPermission.php`, `routes/routes.php`; Tests (feature/HTTP).

- [ ] **`RequireAuditPermission`** — copy flags' `RequireFlagsPermission` exactly, swapping the resource
  to `'audit'`; register in `services()` with `'alias' => ['audit_permission']`.
- [ ] **`routes/routes.php`** (loaded gated on `audit.routes_enabled`):
```php
$router->group(['prefix' => '/audit-logs', 'middleware' => ['auth']], function (Router $router): void {
    $router->get('', [AuditLogController::class, 'index'])->middleware('audit_permission:audit.view');
    $router->get('/{uuid}', [AuditLogController::class, 'show'])->middleware('audit_permission:audit.view');
});
```
- [ ] **`AuditLogController::index`** — read filters from query, call `AuditLogRepository::paginateFiltered`,
  return `Response::paginated($items, $total, $page, $perPage, null, 'Audit log retrieved.')`. `show` →
  `Response::success` / `Response::notFound`. Add `#[ApiOperation]` + `#[ApiResponse(200, collection: true,
  schema: AuditLogData::class)]` (+ 401/403). **No write routes.**
- [ ] **`AuditLogData`** — typed DTO of a row (for OpenAPI).
- [ ] **Tests:** list returns paginated rows; each filter narrows; `audit.view` required (403 without).
- [ ] Commit: `feat: audit-logs read API`.

### Task 3.8: Retention — `audit:prune`

**Files:** `src/Console/PruneAuditLogsCommand.php` (`#[AsCommand('audit:prune')]`, auto-discovered); Test.
- [ ] Delete rows where `occurred_at < now - retention_days` (batched). Model on `LogCleanupTask`.
- [ ] Commit: `feat: audit:prune retention command`.

### Task 3.9: Wiring + boot integration test

**Files:** finalize `AuditServiceProvider::boot()`/`services()`; Test `tests/.../BootIntegrationTest.php`.

- [ ] **`services()`** registers `AuditRecorder`, `AuditSubscriber`, `AegisAuditSubscriber`,
  `AuditLogRepository`, `ActorResolver`, `RequireAuditPermission` (alias `audit_permission`),
  `AuditLogController`, `PruneAuditLogsCommand`.
- [ ] **`boot()`** = exact spec code (compute `rbacSemantic = capture.rbac && class_exists(RoleAssignedEvent)`,
  expose `audit.rbac_semantic_active`, subscribe `AuditSubscriber`, conditionally `AegisAuditSubscriber`,
  load routes/migrations/commands).
- [ ] **Tests:** (a) with Aegis present → `AegisAuditSubscriber` active, pivots suppressed; (b) with
  Aegis **absent** (simulate by config `capture.rbac=false`, or a test without the aegis package) → boots
  fine, no class-not-found, `role_permissions` falls back to generic, `user_roles`/`user_permissions`
  unaudited (documented).
- [ ] Commit: `feat: wire audit subscribers + boot`.

> **Phase-3 gate:** audit `composer test`/`analyse`/`phpcs` green.

---

## Phase 4 — Release, pin, consume

- [ ] **4.1** Release **framework** with `EntityDeletedEvent` + `protected dispatchEvent` (bump per its
  release skill). Note the version.
- [ ] **4.2** Release **aegis** with the six events; set its `require-dev`/`requires.glueful` to the new
  framework. Note the version.
- [ ] **4.3** Pin **audit**: set `require-dev` framework/aegis and `extra.glueful.requires.glueful` to the
  released framework version (Aegis stays `suggest` + dev-only). Tag `1.0.0`.
- [ ] **4.4** (separate, later) Lemma consumes it: enable `glueful/audit`, wire the `audit:prune` schedule,
  and build the Audit Log page against `GET /v1/audit-logs` (and repoint the deferred Users "Activity
  tab" at the same endpoint filtered by `actor`). **Out of scope for this plan** — its own task.

---

## Cross-cutting acceptance (from the spec — verify at the end)

- [ ] login/failed-login/logout rows exist and **carry no token values** anywhere.
- [ ] user create/update/**delete** produce `created`/`updated`/`deleted` rows (delete: `changes=null`,
  label from pre-delete record).
- [ ] **With Aegis:** role assign → one `role_assigned` (no duplicate `user_roles` row); revoke →
  `role_revoked`; role↔permission → `role_permission_assigned`/`_revoked`; **exactly-once** from every
  entry point; no-ops emit nothing.
- [ ] **Without Aegis / `capture.rbac=false`:** boots; `role_permissions` falls back to generic;
  `user_roles`/`user_permissions` unaudited (documented).
- [ ] recursion guard holds (audit write emits no audit row); ignored tables produce none.
- [ ] `GET /v1/audit-logs` filters + paginates; `audit.view` required (403 without).
- [ ] `audit:prune` deletes past the retention window; `AUDIT_ENABLED=false` stops recording;
  `routes_enabled=false` removes the endpoint.
- [ ] All three repos' CI (test + analyse + phpcs) pass.

## Notes for implementers

- **Not Laravel.** Use the verified Glueful APIs above (events via `dispatchEvent`/`EventService`,
  `BaseRepository`, `SchemaBuilder`, `Response::paginated`, `Permission::define`, `ServiceProvider`).
- **The recursion guard and the token allow-list are non-negotiable** — both have dedicated tests.
- **Determinism on the producer side** (Phase 2) is the highest-risk area: the pre-coding context
  verification and the exactly-once-per-entry-point tests are gating, not optional.
- Match each repo's existing test layout/bootstrap (framework vs flags-style) before writing tests.
