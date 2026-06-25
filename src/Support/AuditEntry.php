<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Support;

/**
 * Immutable value object holding one normalized audit row before it is written.
 *
 * Every audit source (entity events, auth events, RBAC domain events) builds one
 * of these; {@see \Glueful\Extensions\Audit\Services\AuditRecorder} turns it into a
 * raw insert. "Actor X did action Y to target Z at time T."
 */
final class AuditEntry
{
    /**
     * @param string|float          $occurredAt  Event time (epoch float/seconds or a datetime string).
     * @param string|null            $actorUuid   Who (null = system/anonymous).
     * @param string|null            $actorLabel  Cached actor display label.
     * @param string                 $action      Verb: created/updated/deleted/login/...
     * @param string                 $category    auth/rbac/user/content/security/data.
     * @param string|null            $targetType  Entity/table type: user/role/permission/...
     * @param string|null            $targetUuid  Which target.
     * @param string|null            $targetLabel Cached target display label.
     * @param array<string,mixed>|null $changes   `{field: {from, to}}` for updates; null otherwise.
     * @param array<string,mixed>|null $context   `{ip, user_agent, request_id, session_uuid, event_id}`.
     */
    public function __construct(
        public readonly string|float $occurredAt,
        public readonly string $action,
        public readonly string $category,
        public readonly ?string $actorUuid = null,
        public readonly ?string $actorLabel = null,
        public readonly ?string $targetType = null,
        public readonly ?string $targetUuid = null,
        public readonly ?string $targetLabel = null,
        public readonly ?array $changes = null,
        public readonly ?array $context = null,
    ) {
    }
}
