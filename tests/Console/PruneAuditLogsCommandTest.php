<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Tests\Console;

use Glueful\Extensions\Audit\Console\PruneAuditLogsCommand;
use Glueful\Extensions\Audit\Tests\Support\AuditTestCase;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * Retention test: seed old + recent rows, run audit:prune, assert only rows past
 * the retention window are deleted and the deleted count is reported.
 */
final class PruneAuditLogsCommandTest extends AuditTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->runMigration();
        $this->context->mergeConfigDefaults('audit', ['retention_days' => 30]);
    }

    public function testPrunesRowsOlderThanRetentionWindow(): void
    {
        // 3 old (well past 30 days) + 2 recent (within the window).
        $this->seedRow('old-1', date('Y-m-d H:i:s', strtotime('-400 days')));
        $this->seedRow('old-2', date('Y-m-d H:i:s', strtotime('-90 days')));
        $this->seedRow('old-3', date('Y-m-d H:i:s', strtotime('-31 days')));
        $this->seedRow('new-1', date('Y-m-d H:i:s', strtotime('-29 days')));
        $this->seedRow('new-2', date('Y-m-d H:i:s', strtotime('-1 days')));

        self::assertSame(5, $this->rowCount());

        $tester = new CommandTester($this->command());
        $exit = $tester->execute([]);

        self::assertSame(0, $exit);
        self::assertSame(2, $this->rowCount());

        $remaining = $this->remainingUuids();
        self::assertContains('new-1', $remaining);
        self::assertContains('new-2', $remaining);
        self::assertNotContains('old-1', $remaining);
        self::assertNotContains('old-3', $remaining);

        self::assertStringContainsString('3', $tester->getDisplay());
    }

    public function testPrunesNothingWhenAllRowsAreRecent(): void
    {
        $this->seedRow('new-1', date('Y-m-d H:i:s', strtotime('-1 days')));
        $this->seedRow('new-2', date('Y-m-d H:i:s'));

        $tester = new CommandTester($this->command());
        self::assertSame(0, $tester->execute([]));
        self::assertSame(2, $this->rowCount());
    }

    private function command(): PruneAuditLogsCommand
    {
        // Pass the test container + context so db($context) resolves the in-test SQLite
        // connection rather than a freshly-built default container.
        return new PruneAuditLogsCommand($this->context->getContainer(), $this->context);
    }

    private function seedRow(string $uuid, string $occurredAt): void
    {
        $this->connection->table('audit_logs')->insert([
            'uuid' => $uuid,
            'occurred_at' => $occurredAt,
            'actor_uuid' => null,
            'actor_label' => 'system',
            'action' => 'created',
            'category' => 'data',
            'target_type' => 'thing',
            'target_uuid' => $uuid,
            'target_label' => null,
            'changes' => null,
            'context' => null,
            'created_at' => $occurredAt,
        ]);
    }

    private function rowCount(): int
    {
        return (int) $this->connection->getPDO()
            ->query('SELECT COUNT(*) FROM audit_logs')
            ->fetchColumn();
    }

    /**
     * @return list<string>
     */
    private function remainingUuids(): array
    {
        /** @var list<string> $uuids */
        $uuids = $this->connection->getPDO()
            ->query('SELECT uuid FROM audit_logs')
            ->fetchAll(\PDO::FETCH_COLUMN);

        return $uuids;
    }
}
