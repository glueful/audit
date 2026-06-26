<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Events;

use Glueful\Bootstrap\ApplicationContext;
use Glueful\Events\Auth\AuthenticationFailedEvent;
use Glueful\Events\Auth\RateLimitExceededEvent;
use Glueful\Events\Auth\SessionCreatedEvent;
use Glueful\Events\Auth\SessionDestroyedEvent;
use Glueful\Events\Contracts\BaseEvent;
use Glueful\Events\Database\EntityCreatedEvent;
use Glueful\Events\Database\EntityDeletedEvent;
use Glueful\Events\Database\EntityUpdatedEvent;
use Glueful\Events\EventSubscriberInterface;
use Glueful\Events\Security\AdminSecurityViolationEvent;
use Glueful\Extensions\Audit\Contracts\AuditableEvent;
use Glueful\Extensions\Audit\Services\AuditRecorder;
use Glueful\Extensions\Audit\Support\ActorResolver;
use Glueful\Extensions\Audit\Support\AuditEntry;
use Symfony\Component\HttpFoundation\Request;
use Throwable;

/**
 * Core/auth/entity audit subscriber.
 *
 * Maps the framework's database, auth, and security events onto normalized
 * {@see AuditEntry} rows written through the {@see AuditRecorder}. Three rules
 * are load-bearing and individually tested:
 *
 *  1. Recursion guard / ignore filtering — entity handlers skip the `audit_logs`
 *     table, the configured `ignore_tables` deny-list, and (conditionally) the
 *     RBAC assignment pivots when the Aegis semantic subscriber is active.
 *  2. Auth token allow-list — the auth handlers build their rows from an explicit
 *     field allow-list and NEVER touch getTokens()/getAccessToken(), so no
 *     access/refresh token value is ever serialized into a row.
 *  3. Capture toggles — each handler no-ops when its capture group is off.
 */
final class AuditSubscriber implements EventSubscriberInterface
{
    /**
     * The explicit allow-list of fields auth rows may carry. The event objects
     * expose live tokens (SessionCreatedEvent::getTokens(),
     * SessionDestroyedEvent::getAccessToken()); building rows from this list — and
     * never from the event wholesale — guarantees no token value is serialized.
     */
    private const AUTH_ALLOWED_FIELDS = [
        'user_uuid',
        'username',
        'reason',
        'ip',
        'user_agent',
        'event_id',
    ];

    private ?Request $request = null;
    private bool $requestResolved = false;

    public function __construct(
        private readonly AuditRecorder $recorder,
        private readonly ActorResolver $actorResolver,
        private readonly ApplicationContext $context,
    ) {
    }

    /**
     * @return array<string, string>
     */
    public static function getSubscribedEvents(): array
    {
        return [
            EntityCreatedEvent::class => 'onEntityCreated',
            EntityUpdatedEvent::class => 'onEntityUpdated',
            EntityDeletedEvent::class => 'onEntityDeleted',
            AuthenticationFailedEvent::class => 'onAuthFailed',
            SessionCreatedEvent::class => 'onSessionCreated',
            SessionDestroyedEvent::class => 'onSessionDestroyed',
            RateLimitExceededEvent::class => 'onRateLimitExceeded',
            AdminSecurityViolationEvent::class => 'onSecurityViolation',
            // App / extension events opt in by implementing AuditableEvent; the framework's
            // InheritanceResolver delivers any implementer dispatched through the bus to here.
            AuditableEvent::class => 'onAuditableEvent',
        ];
    }

    /**
     * Override the resolved request (test seam / explicit wiring). Defaults to
     * lazy container resolution.
     */
    public function withRequest(?Request $request): self
    {
        $this->request = $request;
        $this->requestResolved = true;

        return $this;
    }

    // ---- Entity events --------------------------------------------------------

    public function onEntityCreated(EntityCreatedEvent $event): void
    {
        if (!$this->capturing('entities') || $this->skipTable($event->getTable())) {
            return;
        }

        $entity = $this->toArray($event->getEntity());
        $actor = $this->actor();
        $this->record(new AuditEntry(
            occurredAt: $event->getTimestamp(),
            action: 'created',
            category: $this->category($event->getTable()),
            actorUuid: $actor['actor_uuid'],
            actorLabel: $actor['actor_label'],
            targetType: $this->targetType($event->getTable()),
            targetUuid: $this->stringOrNull($event->getEntityId()),
            targetLabel: $this->label($entity),
            changes: null,
            context: $this->entityContext($event->getEventId()),
        ));
    }

    public function onEntityUpdated(EntityUpdatedEvent $event): void
    {
        if (!$this->capturing('entities') || $this->skipTable($event->getTable())) {
            return;
        }

        $entity = $this->toArray($event->getEntity());
        $actor = $this->actor();
        $this->record(new AuditEntry(
            occurredAt: $event->getTimestamp(),
            action: 'updated',
            category: $this->category($event->getTable()),
            actorUuid: $actor['actor_uuid'],
            actorLabel: $actor['actor_label'],
            targetType: $this->targetType($event->getTable()),
            targetUuid: $this->stringOrNull($event->getEntityId()),
            targetLabel: $this->label($entity),
            changes: $this->shapeChanges($event->getChanges()),
            context: $this->entityContext($event->getEventId()),
        ));
    }

    public function onEntityDeleted(EntityDeletedEvent $event): void
    {
        if (!$this->capturing('entities') || $this->skipTable($event->getTable())) {
            return;
        }

        $original = $this->toArray($event->getOriginalData());
        $actor = $this->actor();
        $this->record(new AuditEntry(
            occurredAt: $event->getTimestamp(),
            action: 'deleted',
            category: $this->category($event->getTable()),
            actorUuid: $actor['actor_uuid'],
            actorLabel: $actor['actor_label'],
            targetType: $this->targetType($event->getTable()),
            targetUuid: $this->stringOrNull($event->getEntityId()),
            targetLabel: $this->label($original),
            // We record THAT it was deleted, not a full snapshot of the row.
            changes: null,
            context: $this->entityContext($event->getEventId()),
        ));
    }

    // ---- Auth events ----------------------------------------------------------

    public function onAuthFailed(AuthenticationFailedEvent $event): void
    {
        if (!$this->capturing('auth')) {
            return;
        }

        // Allow-list only — never serialize the event wholesale.
        $fields = [
            'username' => $event->getUsername(),
            'reason' => $event->getReason(),
            'ip' => $event->getClientIp(),
            'user_agent' => $event->getUserAgent(),
            'event_id' => $event->getEventId(),
        ];

        $this->record(new AuditEntry(
            occurredAt: $event->getTimestamp(),
            action: 'login_failed',
            category: 'auth',
            actorUuid: null,
            actorLabel: $event->getUsername(),
            targetType: 'user',
            targetUuid: null,
            targetLabel: $event->getUsername(),
            changes: ['reason' => ['to' => $event->getReason()]],
            context: $this->authContext($fields),
        ));
    }

    public function onSessionCreated(SessionCreatedEvent $event): void
    {
        if (!$this->capturing('auth')) {
            return;
        }

        $actor = $this->actor();

        // Allow-list ONLY. getTokens()/getAccessToken() are deliberately untouched.
        $fields = [
            'user_uuid' => $event->getUserUuid(),
            'username' => $event->getUsername(),
            'ip' => $actor['ip'],
            'user_agent' => $actor['user_agent'],
            'event_id' => $event->getEventId(),
        ];

        $this->record(new AuditEntry(
            occurredAt: $event->getTimestamp(),
            action: 'login',
            category: 'auth',
            actorUuid: $event->getUserUuid(),
            actorLabel: $event->getUsername(),
            targetType: 'user',
            targetUuid: $event->getUserUuid(),
            targetLabel: $event->getUsername(),
            changes: null,
            context: $this->authContext($fields),
        ));
    }

    public function onSessionDestroyed(SessionDestroyedEvent $event): void
    {
        if (!$this->capturing('auth')) {
            return;
        }

        $actor = $this->actor();

        // Allow-list ONLY. The event exposes getAccessToken() — never read here.
        $fields = [
            'user_uuid' => $event->getUserUuid(),
            'reason' => $event->getReason(),
            'ip' => $actor['ip'],
            'user_agent' => $actor['user_agent'],
            'event_id' => $event->getEventId(),
        ];

        $this->record(new AuditEntry(
            occurredAt: $event->getTimestamp(),
            action: 'logout',
            category: 'auth',
            actorUuid: $event->getUserUuid(),
            actorLabel: null,
            targetType: 'user',
            targetUuid: $event->getUserUuid(),
            targetLabel: null,
            changes: ['reason' => ['to' => $event->getReason()]],
            context: $this->authContext($fields),
        ));
    }

    // ---- Security events ------------------------------------------------------

    public function onRateLimitExceeded(RateLimitExceededEvent $event): void
    {
        if (!$this->capturing('security')) {
            return;
        }

        $this->record(new AuditEntry(
            occurredAt: $event->getTimestamp(),
            action: 'rate_limit_exceeded',
            category: 'security',
            targetType: 'rate_limit',
            targetUuid: null,
            targetLabel: $event->getRule(),
            changes: [
                'count' => ['to' => $event->getCurrentCount()],
                'limit' => ['to' => $event->getLimit()],
            ],
            context: $this->authContext([
                'ip' => $event->getClientIp(),
                'rule' => $event->getRule(),
                'event_id' => $event->getEventId(),
            ]),
        ));
    }

    public function onSecurityViolation(AdminSecurityViolationEvent $event): void
    {
        if (!$this->capturing('security')) {
            return;
        }

        $this->record(new AuditEntry(
            occurredAt: $event->getTimestamp(),
            action: 'security_violation',
            category: 'security',
            actorUuid: $event->userUuid !== '' ? $event->userUuid : null,
            targetType: $event->violationType,
            targetUuid: $event->userUuid !== '' ? $event->userUuid : null,
            targetLabel: null,
            changes: ['message' => ['to' => $event->message]],
            context: $this->authContext([
                'ip' => $event->request->getClientIp(),
                'request_method' => $event->request->getMethod(),
                'event_id' => $event->getEventId(),
            ]),
        ));
    }

    // ---- App / extension events ----------------------------------------------

    /**
     * Record any dispatched event that opted in via {@see AuditableEvent}.
     *
     * The event supplies the semantic fields; the subscriber resolves the actor and request
     * context. occurred_at / event_id come from the framework {@see BaseEvent} when the event
     * is one (the framework convention), otherwise they fall back to "now" / no id.
     */
    public function onAuditableEvent(AuditableEvent $event): void
    {
        if (!$this->capturing('custom')) {
            return;
        }

        $target = $event->auditTarget();
        $actor = $this->actor();

        $occurredAt = $event instanceof BaseEvent ? $event->getTimestamp() : microtime(true);
        $eventId = $event instanceof BaseEvent ? $event->getEventId() : null;

        $context = array_filter([
            'ip' => $actor['ip'],
            'user_agent' => $actor['user_agent'],
            'request_id' => $actor['request_id'],
            'event_id' => $eventId,
        ], static fn ($v): bool => $v !== null && $v !== '');
        // App-supplied metadata is merged last so it wins on key collisions (redaction still applies).
        $context = array_merge($context, $event->auditMetadata());

        $this->record(new AuditEntry(
            occurredAt: $occurredAt,
            action: $event->auditAction(),
            category: $event->auditCategory(),
            actorUuid: $actor['actor_uuid'],
            actorLabel: $actor['actor_label'],
            targetType: $this->stringOrNull($target['type'] ?? null),
            targetUuid: $this->stringOrNull($target['uuid'] ?? null),
            targetLabel: $this->stringOrNull($target['label'] ?? null),
            changes: $event->auditChanges(),
            context: $context !== [] ? $context : null,
        ));
    }

    // ---- Helpers --------------------------------------------------------------

    private function record(AuditEntry $entry): void
    {
        try {
            $this->recorder->record($entry);
        } catch (Throwable) {
            // Never break the audited operation.
        }
    }

    private function capturing(string $group): bool
    {
        return (bool) config($this->context, 'audit.capture.' . $group, true);
    }

    /**
     * Recursion guard + deny-list + conditional RBAC-pivot suppression.
     */
    private function skipTable(string $table): bool
    {
        if ($table === 'audit_logs') {
            return true;
        }

        $ignored = config($this->context, 'audit.ignore_tables', []);
        if (is_array($ignored) && in_array($table, $ignored, true)) {
            return true;
        }

        // Conditional pivot suppression: only suppress the RBAC pivots when the
        // Aegis semantic subscriber is active (else the generic row is the fallback).
        if ((bool) config($this->context, 'audit.rbac_semantic_active', false)) {
            $pivots = config($this->context, 'audit.rbac_pivot_tables', []);
            if (is_array($pivots) && in_array($table, $pivots, true)) {
                return true;
            }
        }

        return false;
    }

    private function category(string $table): string
    {
        $overrides = config($this->context, 'audit.category_map', []);
        if (is_array($overrides) && isset($overrides[$table]) && is_string($overrides[$table])) {
            return $overrides[$table];
        }

        return match (true) {
            in_array($table, ['users', 'profiles'], true) => 'user',
            in_array($table, ['roles', 'permissions', 'user_roles', 'user_permissions', 'role_permissions'], true)
                => 'rbac',
            str_starts_with($table, 'content_') || $table === 'entries' => 'content',
            default => 'data',
        };
    }

    private function targetType(string $table): string
    {
        return match ($table) {
            'users', 'profiles' => 'user',
            'roles' => 'role',
            'permissions' => 'permission',
            'entries' => 'content_entry',
            default => $table,
        };
    }

    /**
     * Best-effort display label from the entity payload.
     *
     * @param array<string,mixed> $entity
     */
    private function label(array $entity): ?string
    {
        foreach (['name', 'title', 'display_title', 'email', 'username', 'slug'] as $key) {
            if (isset($entity[$key]) && is_scalar($entity[$key]) && (string) $entity[$key] !== '') {
                return (string) $entity[$key];
            }
        }

        return null;
    }

    /**
     * Shape raw event changes into {field: {from?, to}}.
     *
     * @param array<string,mixed> $changes
     * @return array<string,array<string,mixed>>|null
     */
    private function shapeChanges(array $changes): ?array
    {
        if ($changes === []) {
            return null;
        }

        $shaped = [];
        foreach ($changes as $field => $value) {
            if (is_array($value) && (array_key_exists('to', $value) || array_key_exists('from', $value))) {
                // Already in {from?, to} form — keep what's there.
                $shaped[(string) $field] = $value;
                continue;
            }
            $shaped[(string) $field] = ['to' => $value];
        }

        return $shaped;
    }

    /**
     * @return array<string,mixed>
     */
    private function entityContext(string $eventId): array
    {
        $actor = $this->actor();

        return array_filter([
            'ip' => $actor['ip'],
            'user_agent' => $actor['user_agent'],
            'request_id' => $actor['request_id'],
            'event_id' => $eventId,
        ], static fn ($v): bool => $v !== null);
    }

    /**
     * Build an auth/security context from an explicit allow-listed field map.
     * Any unknown key is dropped; null values are dropped.
     *
     * @param array<string,mixed> $fields
     * @return array<string,mixed>
     */
    private function authContext(array $fields): array
    {
        $allowed = array_merge(self::AUTH_ALLOWED_FIELDS, ['rule', 'request_method', 'request_id']);

        $context = [];
        foreach ($fields as $key => $value) {
            if ($value === null) {
                continue;
            }
            if (!in_array($key, $allowed, true)) {
                continue;
            }
            // user_uuid travels as actor/target columns; keep request metadata in context.
            if ($key === 'user_uuid' || $key === 'username' || $key === 'reason') {
                continue;
            }
            $context[$key] = $value;
        }

        return $context;
    }

    /**
     * Resolved actor + request context (entity events carry no actor).
     *
     * @return array{actor_uuid:string|null,actor_label:string|null,ip:string|null,user_agent:string|null,request_id:string|null}
     */
    private function actor(): array
    {
        return $this->actorResolver->resolve($this->currentRequest());
    }

    private function currentRequest(): ?Request
    {
        if ($this->requestResolved) {
            return $this->request;
        }

        $this->requestResolved = true;
        $this->request = null;

        try {
            if ($this->context->hasContainer()) {
                $container = $this->context->getContainer();
                if ($container->has(Request::class)) {
                    $resolved = $container->get(Request::class);
                    if ($resolved instanceof Request) {
                        $this->request = $resolved;
                    }
                }
            }
        } catch (Throwable) {
            $this->request = null;
        }

        return $this->request;
    }

    /**
     * @param array<string,mixed>|object $value
     * @return array<string,mixed>
     */
    private function toArray(array|object $value): array
    {
        if (is_array($value)) {
            return $value;
        }

        if ($value instanceof \JsonSerializable) {
            $serialized = $value->jsonSerialize();
            return is_array($serialized) ? $serialized : (array) $value;
        }

        return get_object_vars($value);
    }

    private function stringOrNull(mixed $value): ?string
    {
        if ($value === null) {
            return null;
        }

        return is_scalar($value) ? (string) $value : null;
    }
}
