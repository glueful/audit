<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Tests\Repositories;

use Glueful\Extensions\Audit\Repositories\AuditLogRepository;
use Glueful\Extensions\Audit\Tests\Support\AuditTestCase;

final class AuditLogRepositoryTest extends AuditTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->runMigration();
        $this->seed();
    }

    public function testFiltersByActor(): void
    {
        $result = $this->repo()->paginateFiltered(['actor' => 'actor-a'], 1, 25);

        self::assertSame(2, $result['total']);
        foreach ($result['data'] as $row) {
            self::assertSame('actor-a', $row['actor_uuid']);
        }
    }

    public function testFiltersByAction(): void
    {
        $result = $this->repo()->paginateFiltered(['action' => 'login'], 1, 25);

        self::assertSame(1, $result['total']);
        self::assertSame('login', $result['data'][0]['action']);
    }

    public function testFiltersByCategory(): void
    {
        $result = $this->repo()->paginateFiltered(['category' => 'rbac'], 1, 25);

        self::assertSame(2, $result['total']);
        foreach ($result['data'] as $row) {
            self::assertSame('rbac', $row['category']);
        }
    }

    public function testFiltersByTargetTypeAndUuid(): void
    {
        $result = $this->repo()->paginateFiltered([
            'target_type' => 'role',
            'target_uuid' => 'role-1',
        ], 1, 25);

        self::assertSame(1, $result['total']);
        self::assertSame('role-1', $result['data'][0]['target_uuid']);
    }

    public function testFiltersByFromAndTo(): void
    {
        $from = $this->repo()->paginateFiltered(['from' => '2026-06-25 10:00:00'], 1, 25);
        self::assertSame(3, $from['total']);

        $to = $this->repo()->paginateFiltered(['to' => '2026-06-24 23:59:59'], 1, 25);
        self::assertSame(2, $to['total']);

        $window = $this->repo()->paginateFiltered([
            'from' => '2026-06-24 00:00:00',
            'to' => '2026-06-25 23:59:59',
        ], 1, 25);
        // 06-24 09:00, 06-25 10:00, 06-25 11:00, 06-25 12:00.
        self::assertSame(4, $window['total']);
    }

    public function testOrdersByOccurredAtDescending(): void
    {
        $result = $this->repo()->paginateFiltered([], 1, 25);

        $timestamps = array_column($result['data'], 'occurred_at');
        $sorted = $timestamps;
        rsort($sorted);
        self::assertSame($sorted, $timestamps);
        self::assertSame('2026-06-25 12:00:00', $timestamps[0]);
    }

    public function testPaginationMeta(): void
    {
        $result = $this->repo()->paginateFiltered([], 1, 2);

        self::assertSame(5, $result['total']);
        self::assertSame(1, $result['current_page']);
        self::assertSame(2, $result['per_page']);
        self::assertSame(3, $result['total_pages']);
        self::assertCount(2, $result['data']);
    }

    private function repo(): AuditLogRepository
    {
        return new AuditLogRepository($this->connection, $this->context);
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
