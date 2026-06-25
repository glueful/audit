<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Repositories;

use Glueful\Repository\BaseRepository;

/**
 * Read store for the audit trail.
 *
 * Reads go through BaseRepository (only WRITES must avoid it — those run through
 * {@see \Glueful\Extensions\Audit\Services\AuditRecorder} as raw inserts). The table
 * is append-only and has no `updated_at` column.
 */
final class AuditLogRepository extends BaseRepository
{
    public function getTableName(): string
    {
        return 'audit_logs';
    }

    /** audit_logs is append-only — no updated_at column. */
    protected bool $hasUpdatedAt = false;

    /**
     * Filtered, paginated audit feed (newest first).
     *
     * Supported filters (all optional): `actor` (→ actor_uuid), `action`, `category`,
     * `target_type`, `target_uuid`, `from`/`to` (occurred_at >= / <= a timestamp).
     *
     * @param array<string,mixed> $filters
     * @return array{
     *   data: array<int, array<string, mixed>>,
     *   current_page: int,
     *   per_page: int,
     *   total: int,
     *   last_page: int,
     *   total_pages: int,
     *   has_more: bool,
     *   from: int,
     *   to: int,
     *   execution_time_ms: int
     * }
     */
    public function paginateFiltered(array $filters, int $page, int $perPage): array
    {
        $query = $this->db->table($this->table)->select(['*']);

        $equals = [
            'actor' => 'actor_uuid',
            'action' => 'action',
            'category' => 'category',
            'target_type' => 'target_type',
            'target_uuid' => 'target_uuid',
        ];

        foreach ($equals as $filterKey => $column) {
            $value = $filters[$filterKey] ?? null;
            if (is_string($value) && $value !== '') {
                $query->where($column, '=', $value);
            }
        }

        $from = $filters['from'] ?? null;
        if (is_string($from) && $from !== '') {
            $query->where('occurred_at', '>=', $from);
        }

        $to = $filters['to'] ?? null;
        if (is_string($to) && $to !== '') {
            $query->where('occurred_at', '<=', $to);
        }

        $query->orderBy('occurred_at', 'DESC');

        /** @var array{data: array<int, array<string, mixed>>, current_page: int, per_page: int, total: int, last_page: int, has_more: bool, from: int, to: int, execution_time_ms: int} $result */
        $result = $query->paginate($page, $perPage);

        // The query builder envelope names the page count `last_page`; expose it also as
        // `total_pages` so the API response shape matches the framework `paginate()` envelope.
        return array_merge($result, ['total_pages' => $result['last_page']]);
    }
}
