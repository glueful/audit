<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Http\DTOs;

/**
 * Typed shape of one audit_logs row for the read API (OpenAPI documentation).
 *
 * Mirrors the normalized table: "actor X did action Y to target Z at time T".
 * Append-only — there is no write/update DTO.
 */
final class AuditLogData
{
    /**
     * @param string                    $uuid        NanoID of the row.
     * @param string                    $occurred_at Event time (datetime string).
     * @param string|null               $actor_uuid  Who acted (null = system/anonymous).
     * @param string|null               $actor_label Cached actor display label.
     * @param string                    $action      Verb: created/updated/deleted/login/...
     * @param string                    $category    auth/rbac/user/content/security/data.
     * @param string|null               $target_type Entity/table type: user/role/permission/...
     * @param string|null               $target_uuid Which target.
     * @param string|null               $target_label Cached target display label.
     * @param array<string,mixed>|null  $changes     `{field: {from?, to}}` for updates; null otherwise.
     * @param array<string,mixed>|null  $context     `{ip, user_agent, request_id, event_id, ...}`.
     * @param string|null               $created_at  Insert time (≈ occurred_at).
     */
    public function __construct(
        public readonly string $uuid,
        public readonly string $occurred_at,
        public readonly ?string $actor_uuid,
        public readonly ?string $actor_label,
        public readonly string $action,
        public readonly string $category,
        public readonly ?string $target_type,
        public readonly ?string $target_uuid,
        public readonly ?string $target_label,
        public readonly ?array $changes,
        public readonly ?array $context,
        public readonly ?string $created_at,
    ) {
    }
}
