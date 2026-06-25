<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Tests\Services;

use Glueful\Events\Database\EntityCreatedEvent;
use Glueful\Extensions\Audit\Services\AuditRecorder;
use Glueful\Extensions\Audit\Support\AuditEntry;
use Glueful\Extensions\Audit\Tests\Support\AuditTestCase;

final class AuditRecorderTest extends AuditTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->runMigration();
        // Seed the redaction patterns the recorder reads via config('audit.redact_fields').
        $this->context->mergeConfigDefaults('audit', [
            'redact_fields' => ['password', 'password_hash', 'secret', 'api_key', '*_token'],
        ]);
    }

    public function testRecordWritesNormalizedRow(): void
    {
        $entry = new AuditEntry(
            occurredAt: '2026-06-25 10:00:00',
            action: 'updated',
            category: 'user',
            actorUuid: 'actor-1',
            actorLabel: 'jane@example.com',
            targetType: 'user',
            targetUuid: 'target-1',
            targetLabel: 'Jane',
            changes: ['name' => ['from' => 'Jan', 'to' => 'Jane']],
            context: ['ip' => '127.0.0.1'],
        );

        (new AuditRecorder($this->context))->record($entry);

        $rows = $this->auditRows();
        self::assertCount(1, $rows);
        $row = $rows[0];
        self::assertSame('updated', $row['action']);
        self::assertSame('user', $row['category']);
        self::assertSame('actor-1', $row['actor_uuid']);
        self::assertSame('jane@example.com', $row['actor_label']);
        self::assertSame('user', $row['target_type']);
        self::assertSame('target-1', $row['target_uuid']);
        self::assertSame('Jane', $row['target_label']);
        self::assertSame('2026-06-25 10:00:00', $row['occurred_at']);
        self::assertNotEmpty($row['uuid']);
        self::assertNotEmpty($row['created_at']);
        self::assertSame(['name' => ['from' => 'Jan', 'to' => 'Jane']], json_decode((string) $row['changes'], true));
    }

    public function testRedactsSensitiveFieldsInChangesAndContext(): void
    {
        $entry = new AuditEntry(
            occurredAt: '2026-06-25 10:00:00',
            action: 'updated',
            category: 'user',
            changes: [
                'password' => ['from' => 'old-hash', 'to' => 'new-hash'],
                'name' => ['from' => 'A', 'to' => 'B'],
            ],
            context: [
                'access_token' => 'live-token-value',
                'refresh_token' => 'live-refresh-value',
                'secret' => 'shhh',
                'api_key' => 'gf_live_xxx',
                'nested' => ['client_token' => 't', 'ok' => 'keep'],
                'ip' => '127.0.0.1',
            ],
        );

        (new AuditRecorder($this->context))->record($entry);

        $row = $this->auditRows()[0];
        $changes = json_decode((string) $row['changes'], true);
        $context = json_decode((string) $row['context'], true);

        self::assertSame('[redacted]', $changes['password']);
        self::assertSame(['from' => 'A', 'to' => 'B'], $changes['name']);

        self::assertSame('[redacted]', $context['access_token']);
        self::assertSame('[redacted]', $context['refresh_token']);
        self::assertSame('[redacted]', $context['secret']);
        self::assertSame('[redacted]', $context['api_key']);
        self::assertSame('[redacted]', $context['nested']['client_token']);
        self::assertSame('keep', $context['nested']['ok']);
        self::assertSame('127.0.0.1', $context['ip']);

        // The live token values must not appear anywhere in the serialized row.
        $serialized = (string) $row['changes'] . (string) $row['context'];
        self::assertStringNotContainsString('live-token-value', $serialized);
        self::assertStringNotContainsString('live-refresh-value', $serialized);
    }

    public function testRecordPerformsRawInsertAndEmitsNoEntityEvent(): void
    {
        (new AuditRecorder($this->context))->record(new AuditEntry(
            occurredAt: '2026-06-25 10:00:00',
            action: 'created',
            category: 'user',
        ));

        // Recursion guard: a raw insert must dispatch NO entity event, and certainly
        // no event targeting the audit_logs table.
        self::assertSame([], $this->eventsOfType(EntityCreatedEvent::class));
        self::assertSame([], $this->recordedEvents);
        self::assertCount(1, $this->auditRows());
    }

    public function testRecordDoesNotThrowOnWriteFailure(): void
    {
        // Drop the table so the insert fails; record() must swallow it.
        $this->connection->getSchemaBuilder()->dropTableIfExists('audit_logs');

        (new AuditRecorder($this->context))->record(new AuditEntry(
            occurredAt: '2026-06-25 10:00:00',
            action: 'created',
            category: 'user',
        ));

        // No exception escaped — reaching here is the assertion.
        $this->addToAssertionCount(1);
    }

    /**
     * @return list<array<string,mixed>>
     */
    private function auditRows(): array
    {
        $pdo = $this->connection->getPDO();
        /** @var list<array<string,mixed>> $rows */
        $rows = $pdo->query('SELECT * FROM audit_logs ORDER BY id ASC')->fetchAll(\PDO::FETCH_ASSOC);

        return $rows;
    }
}
