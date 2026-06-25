<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Http\Controllers;

use Glueful\Extensions\Audit\Http\DTOs\AuditLogData;
use Glueful\Extensions\Audit\Repositories\AuditLogRepository;
use Glueful\Http\Response;
use Glueful\Routing\Attributes\ApiOperation;
use Glueful\Routing\Attributes\ApiResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Read API for the append-only audit trail.
 *
 * No write/update/delete actions — immutability is the point. Reads run through
 * {@see AuditLogRepository} (reads via BaseRepository are fine; only WRITES must
 * avoid it, those go through the AuditRecorder raw insert).
 */
final class AuditLogController
{
    private const MAX_PER_PAGE = 100;

    public function __construct(private readonly AuditLogRepository $repository)
    {
    }

    /**
     * List the audit log (filtered, paginated, newest first).
     */
    #[ApiOperation(
        summary: 'List audit log',
        description: 'Returns the normalized, append-only audit trail filtered + paginated (newest first). '
            . 'Filters (all optional query params): `actor` (actor_uuid), `action`, `category`, `target_type`, '
            . '`target_uuid`, `from`/`to` (ISO/datetime bounds on occurred_at), `page`, `per_page` '
            . '(1-100, default 25). Requires the `audit.view` permission.',
        tags: ['Audit'],
    )]
    #[ApiResponse(200, AuditLogData::class, description: 'Audit log retrieved', collection: true)]
    #[ApiResponse(401, description: 'Not authenticated')]
    #[ApiResponse(403, description: 'Missing audit.view permission')]
    public function index(Request $request): Response
    {
        $filters = [
            'actor' => $this->stringParam($request, 'actor'),
            'action' => $this->stringParam($request, 'action'),
            'category' => $this->stringParam($request, 'category'),
            'target_type' => $this->stringParam($request, 'target_type'),
            'target_uuid' => $this->stringParam($request, 'target_uuid'),
            'from' => $this->stringParam($request, 'from'),
            'to' => $this->stringParam($request, 'to'),
        ];

        $page = $this->intParam($request, 'page', 1, 1);
        $perPage = $this->intParam($request, 'per_page', 25, 1, self::MAX_PER_PAGE);

        $result = $this->repository->paginateFiltered($filters, $page, $perPage);

        /** @var list<mixed> $items */
        $items = array_values($result['data']);

        return Response::paginated(
            $items,
            $result['total'],
            $page,
            $perPage,
            null,
            'Audit log retrieved.'
        );
    }

    /**
     * Get a single audit row by uuid.
     */
    #[ApiOperation(
        summary: 'Get audit log entry',
        description: 'Returns a single audit row by its uuid. Requires the `audit.view` permission.',
        tags: ['Audit'],
    )]
    #[ApiResponse(200, AuditLogData::class, description: 'Audit log entry retrieved')]
    #[ApiResponse(401, description: 'Not authenticated')]
    #[ApiResponse(403, description: 'Missing audit.view permission')]
    #[ApiResponse(404, description: 'Audit log entry not found')]
    public function show(Request $request, string $uuid): Response
    {
        $row = $this->repository->findRecordByUuid($uuid);
        if ($row === null) {
            return Response::notFound('Audit log entry not found.');
        }

        return Response::success(['audit_log' => $row], 'Audit log entry retrieved.');
    }

    private function stringParam(Request $request, string $key): ?string
    {
        $value = $request->query->get($key);

        return is_string($value) && $value !== '' ? $value : null;
    }

    private function intParam(Request $request, string $key, int $default, int $min, ?int $max = null): int
    {
        $raw = $request->query->get($key);
        $value = is_numeric($raw) ? (int) $raw : $default;

        if ($value < $min) {
            $value = $min;
        }
        if ($max !== null && $value > $max) {
            $value = $max;
        }

        return $value;
    }
}
