<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Tests;

use Glueful\Extensions\Audit\Tests\Support\AuditTestCase;

final class MigrationSmokeTest extends AuditTestCase
{
    public function testMigrationCreatesAuditLogsTable(): void
    {
        $schema = $this->connection->getSchemaBuilder();
        self::assertFalse($schema->hasTable('audit_logs'), 'audit_logs should not exist before migration');

        $this->runMigration();

        self::assertTrue($schema->hasTable('audit_logs'), 'audit_logs should exist after migration');
    }

    public function testAuditLogsTableHasExpectedColumns(): void
    {
        $this->runMigration();

        $columns = $this->columnNames('audit_logs');

        $expected = [
            'id',
            'uuid',
            'occurred_at',
            'actor_uuid',
            'actor_label',
            'action',
            'category',
            'target_type',
            'target_uuid',
            'target_label',
            'changes',
            'context',
            'created_at',
        ];

        foreach ($expected as $column) {
            self::assertContains($column, $columns, "audit_logs should have column {$column}");
        }
    }

    public function testMigrationIsIdempotent(): void
    {
        $this->runMigration();
        // A second up() must not throw (guarded by hasTable()).
        $this->runMigration();

        self::assertTrue($this->connection->getSchemaBuilder()->hasTable('audit_logs'));
    }

    /**
     * @return list<string>
     */
    private function columnNames(string $table): array
    {
        $pdo = $this->connection->getPDO();
        $rows = $pdo->query('PRAGMA table_info(' . $table . ')')->fetchAll(\PDO::FETCH_ASSOC);

        return array_map(static fn (array $row): string => (string) $row['name'], $rows);
    }
}
