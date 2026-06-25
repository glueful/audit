<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Tests\Http;

use Glueful\Extensions\Audit\Http\Controllers\AuditLogController;
use Glueful\Extensions\Audit\Repositories\AuditLogRepository;
use Glueful\Extensions\Audit\Tests\Support\AuditTestCase;
use Glueful\Http\Response;
use Symfony\Component\HttpFoundation\Request;

/**
 * Read API feature test. The controller is exercised directly with a built Request
 * (the permission middleware + HTTP routing are tested separately), asserting the
 * paginated envelope, the query-filter narrowing, and show() row/404 behaviour.
 */
final class AuditLogControllerTest extends AuditTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->runMigration();
        $this->seed();
    }

    public function testIndexReturnsPaginatedEnvelope(): void
    {
        $response = $this->controller()->index($this->request([]));

        $payload = $this->payload($response);
        self::assertTrue($payload['success']);
        self::assertSame('Audit log retrieved.', $payload['message']);
        self::assertSame(5, $payload['total']);
        self::assertSame(1, $payload['current_page']);
        self::assertSame(25, $payload['per_page']);
        self::assertCount(5, $payload['data']);
        // Newest first.
        self::assertSame('2026-06-25 12:00:00', $payload['data'][0]['occurred_at']);
    }

    public function testIndexFiltersByActor(): void
    {
        $payload = $this->payload($this->controller()->index($this->request(['actor' => 'actor-a'])));

        self::assertSame(2, $payload['total']);
        foreach ($payload['data'] as $row) {
            self::assertSame('actor-a', $row['actor_uuid']);
        }
    }

    public function testIndexFiltersByActionCategoryAndTarget(): void
    {
        self::assertSame(1, $this->payload(
            $this->controller()->index($this->request(['action' => 'login']))
        )['total']);

        self::assertSame(2, $this->payload(
            $this->controller()->index($this->request(['category' => 'rbac']))
        )['total']);

        $byTarget = $this->payload($this->controller()->index($this->request([
            'target_type' => 'role',
            'target_uuid' => 'role-1',
        ])));
        self::assertSame(1, $byTarget['total']);
        self::assertSame('role-1', $byTarget['data'][0]['target_uuid']);
    }

    public function testIndexFiltersByFromAndTo(): void
    {
        self::assertSame(3, $this->payload(
            $this->controller()->index($this->request(['from' => '2026-06-25 10:00:00']))
        )['total']);

        self::assertSame(2, $this->payload(
            $this->controller()->index($this->request(['to' => '2026-06-24 23:59:59']))
        )['total']);
    }

    public function testIndexRespectsPaginationParams(): void
    {
        $payload = $this->payload($this->controller()->index($this->request([
            'page' => '2',
            'per_page' => '2',
        ])));

        self::assertSame(5, $payload['total']);
        self::assertSame(2, $payload['current_page']);
        self::assertSame(2, $payload['per_page']);
        self::assertCount(2, $payload['data']);
    }

    public function testIndexClampsPerPage(): void
    {
        // per_page over the 100 cap is clamped; below 1 floors to 1.
        $payload = $this->payload($this->controller()->index($this->request(['per_page' => '5000'])));
        self::assertSame(100, $payload['per_page']);
    }

    public function testShowReturnsRow(): void
    {
        $response = $this->controller()->show($this->request([]), 'row000000000');

        $payload = $this->payload($response);
        self::assertTrue($payload['success']);
        self::assertSame('login', $payload['data']['audit_log']['action']);
    }

    public function testShowReturns404ForUnknownUuid(): void
    {
        $response = $this->controller()->show($this->request([]), 'does-not-ex');

        self::assertSame(Response::HTTP_NOT_FOUND, $response->getStatusCode());
        $payload = $this->payload($response);
        self::assertFalse($payload['success']);
    }

    private function controller(): AuditLogController
    {
        return new AuditLogController(new AuditLogRepository($this->connection, $this->context));
    }

    /**
     * @param array<string,string> $query
     */
    private function request(array $query): Request
    {
        return new Request($query);
    }

    /**
     * @return array<string,mixed>
     */
    private function payload(Response $response): array
    {
        /** @var array<string,mixed> $decoded */
        $decoded = json_decode((string) $response->getContent(), true);

        return $decoded;
    }

    private function seed(): void
    {
        $rows = [
            ['actor-a', 'login', 'auth', 'user', 'u-1', '2026-06-23 09:00:00'],
            ['actor-a', 'role_assigned', 'rbac', 'user', 'u-1', '2026-06-24 09:00:00'],
            ['actor-b', 'role_permission_assigned', 'rbac', 'role', 'role-1', '2026-06-25 10:00:00'],
            ['actor-b', 'updated', 'user', 'user', 'u-2', '2026-06-25 11:00:00'],
            ['actor-c', 'deleted', 'user', 'user', 'u-3', '2026-06-25 12:00:00'],
        ];

        $table = $this->connection->table('audit_logs');
        foreach ($rows as $i => [$actor, $action, $category, $targetType, $targetUuid, $occurredAt]) {
            $table->insert([
                'uuid' => 'row' . str_pad((string) $i, 9, '0', STR_PAD_LEFT),
                'occurred_at' => $occurredAt,
                'actor_uuid' => $actor,
                'actor_label' => $actor . '@example.com',
                'action' => $action,
                'category' => $category,
                'target_type' => $targetType,
                'target_uuid' => $targetUuid,
                'target_label' => null,
                'changes' => null,
                'context' => null,
                'created_at' => $occurredAt,
            ]);
        }
    }
}
