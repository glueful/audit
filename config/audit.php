<?php

declare(strict_types=1);

return [
    // Runtime kill-switch. The extension itself is opt-in (installed disabled in the
    // registry); once enabled it records by default. Set false to keep the extension
    // installed but inert.
    'enabled' => env('AUDIT_ENABLED', true),

    // Toggle the read API routes (GET /audit-logs).
    'routes_enabled' => env('AUDIT_ROUTES_ENABLED', true),

    // Per-source capture toggles.
    'capture' => [
        'entities' => true,   // EntityCreated/Updated/Deleted
        'auth'     => true,   // login / login_failed / logout
        'security' => true,   // rate-limit / admin security violations
        'rbac'     => true,   // Aegis domain events (only effective when Aegis is installed)
    ],

    // Tables the GENERIC entity subscriber always ignores (deny-list).
    'ignore_tables' => [
        'audit_logs',
        'auth_sessions',
        'refresh_tokens',
        'activity_logs',
        'cache',
        'cache_locks',
        'jobs',
        'job_batches',
        'failed_jobs',
        'sessions',
        'password_reset_tokens',
        'notifications',
        'scheduled_tasks',
    ],

    // RBAC assignment pivots — suppressed from generic capture ONLY when the Aegis
    // semantic subscriber is active (else recorded generically as a fallback, so RBAC
    // is never silently dropped).
    'rbac_pivot_tables' => ['user_roles', 'user_permissions', 'role_permissions'],

    // table => category overrides (defaults derived from table name).
    'category_map' => [],

    // Field-name patterns redacted from changes/context ("*" wildcard supported).
    'redact_fields' => ['password', 'password_hash', 'secret', 'api_key', '*_token'],

    // Retention window for the audit:prune command.
    'retention_days' => env('AUDIT_RETENTION_DAYS', 365),
];
