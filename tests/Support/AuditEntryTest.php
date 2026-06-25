<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Tests\Support;

use Glueful\Extensions\Audit\Support\AuditEntry;
use PHPUnit\Framework\TestCase;

final class AuditEntryTest extends TestCase
{
    public function testHoldsNormalizedFields(): void
    {
        $entry = new AuditEntry(
            occurredAt: '2026-06-25 10:00:00',
            action: 'updated',
            category: 'user',
            actorUuid: 'actor-uuid-1',
            actorLabel: 'jane@example.com',
            targetType: 'user',
            targetUuid: 'target-uuid-1',
            targetLabel: 'Jane',
            changes: ['name' => ['from' => 'Jan', 'to' => 'Jane']],
            context: ['ip' => '127.0.0.1'],
        );

        self::assertSame('2026-06-25 10:00:00', $entry->occurredAt);
        self::assertSame('updated', $entry->action);
        self::assertSame('user', $entry->category);
        self::assertSame('actor-uuid-1', $entry->actorUuid);
        self::assertSame('jane@example.com', $entry->actorLabel);
        self::assertSame('user', $entry->targetType);
        self::assertSame('target-uuid-1', $entry->targetUuid);
        self::assertSame('Jane', $entry->targetLabel);
        self::assertSame(['name' => ['from' => 'Jan', 'to' => 'Jane']], $entry->changes);
        self::assertSame(['ip' => '127.0.0.1'], $entry->context);
    }

    public function testDefaultsAreNull(): void
    {
        $entry = new AuditEntry(
            occurredAt: 1_700_000_000.0,
            action: 'login',
            category: 'auth',
        );

        self::assertSame(1_700_000_000.0, $entry->occurredAt);
        self::assertNull($entry->actorUuid);
        self::assertNull($entry->actorLabel);
        self::assertNull($entry->targetType);
        self::assertNull($entry->targetUuid);
        self::assertNull($entry->targetLabel);
        self::assertNull($entry->changes);
        self::assertNull($entry->context);
    }
}
