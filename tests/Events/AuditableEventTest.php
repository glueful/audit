<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Tests\Events;

use Glueful\Events\Contracts\BaseEvent;
use Glueful\Events\EventDispatcher;
use Glueful\Events\ListenerProvider;
use Glueful\Extensions\Audit\Contracts\AuditableEvent;
use Glueful\Extensions\Audit\Contracts\AuditableEventDefaults;
use Glueful\Extensions\Audit\Events\AuditSubscriber;
use Glueful\Extensions\Audit\Services\AuditRecorder;
use Glueful\Extensions\Audit\Support\ActorResolver;
use Glueful\Extensions\Audit\Tests\Support\AuditTestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The app/extension extension point: any event implementing {@see AuditableEvent} is recorded
 * automatically — the app supplies the semantic fields, the subscriber fills in actor + context.
 */
final class AuditableEventTest extends AuditTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->runMigration();
        $this->context->mergeConfigDefaults('audit', [
            'enabled' => true,
            'capture' => [
                'entities' => true,
                'auth' => true,
                'security' => true,
                'rbac' => true,
                'custom' => true,
            ],
            'ignore_tables' => ['audit_logs'],
            'redact_fields' => ['password', 'secret', 'api_key', '*_token'],
        ]);
    }

    private function subscriber(?Request $request = null): AuditSubscriber
    {
        return (new AuditSubscriber(new AuditRecorder($this->context), new ActorResolver(), $this->context))
            ->withRequest($request);
    }

    public function testRecordsAnAuditableEventViaDirectHandler(): void
    {
        $this->subscriber()->onAuditableEvent(new InvoicePaidFixture('inv-1', 4200));

        $row = $this->onlyRow();
        self::assertSame('paid', $row['action']);
        self::assertSame('billing', $row['category']);
        self::assertSame('invoice', $row['target_type']);
        self::assertSame('inv-1', $row['target_uuid']);
        self::assertSame('Invoice #inv-1', $row['target_label']);

        $context = json_decode((string) $row['context'], true);
        self::assertIsArray($context);
        self::assertSame(4200, $context['amount_cents'] ?? null);
        self::assertArrayHasKey('event_id', $context); // from the framework BaseEvent
    }

    public function testInterfaceRoutingDeliversAConcreteEventToTheSubscriber(): void
    {
        // The subscriber listens on the AuditableEvent INTERFACE; the framework's
        // InheritanceResolver must route a concrete implementer dispatched on the bus to it.
        $provider = new ListenerProvider();
        $provider->addListener(AuditableEvent::class, [$this->subscriber(), 'onAuditableEvent']);

        (new EventDispatcher($provider))->dispatch(new InvoicePaidFixture('inv-9', 100));

        $row = $this->onlyRow();
        self::assertSame('paid', $row['action']);
        self::assertSame('inv-9', $row['target_uuid']);
    }

    public function testDefaultsTraitGivesNoTargetAndNoChanges(): void
    {
        $this->subscriber()->onAuditableEvent(new BareAuditableFixture());

        $row = $this->onlyRow();
        self::assertSame('exported', $row['action']);
        self::assertSame('data', $row['category']);
        self::assertNull($row['target_type']);
        self::assertNull($row['target_uuid']);
        self::assertNull($row['changes']);
    }

    public function testMetadataIsMergedIntoContextAndRedacted(): void
    {
        $this->subscriber()->onAuditableEvent(
            new InvoicePaidFixture('inv-2', 100, ['api_key' => 'sk_live_secret', 'gateway' => 'stripe'])
        );

        $context = json_decode((string) $this->onlyRow()['context'], true);
        self::assertIsArray($context);
        self::assertSame('stripe', $context['gateway'] ?? null);
        self::assertSame('[redacted]', $context['api_key'] ?? null);
    }

    public function testChangesArePersisted(): void
    {
        $this->subscriber()->onAuditableEvent(
            new EntryUpdatedFixture('entry-1', ['title' => ['from' => 'A', 'to' => 'B']])
        );

        $row = $this->onlyRow();
        self::assertSame('updated', $row['action']);
        self::assertSame('content', $row['category']);
        $changes = json_decode((string) $row['changes'], true);
        self::assertIsArray($changes);
        self::assertSame(['from' => 'A', 'to' => 'B'], $changes['title'] ?? null);
    }

    public function testActorIsResolvedFromTheRequest(): void
    {
        $request = Request::create('/x', 'POST');
        // The always-present post-auth `'user'` array attribute.
        $request->attributes->set('user', ['uuid' => 'admin-1', 'email' => 'admin@example.com']);

        $this->subscriber($request)->onAuditableEvent(new InvoicePaidFixture('inv-3', 1));

        $row = $this->onlyRow();
        self::assertSame('admin-1', $row['actor_uuid']);
        self::assertSame('admin@example.com', $row['actor_label']);
    }

    /**
     * @return list<array<string,mixed>>
     */
    private function rows(): array
    {
        $pdo = $this->connection->getPDO();
        /** @var list<array<string,mixed>> $rows */
        $rows = $pdo->query('SELECT * FROM audit_logs ORDER BY id ASC')->fetchAll(\PDO::FETCH_ASSOC);

        return $rows;
    }

    /**
     * @return array<string,mixed>
     */
    private function onlyRow(): array
    {
        $rows = $this->rows();
        self::assertCount(1, $rows);

        return $rows[0];
    }
}

/**
 * Minimal app event: only the two required verbs plus a target; the rest comes from the trait.
 */
final class InvoicePaidFixture extends BaseEvent implements AuditableEvent
{
    use AuditableEventDefaults;

    /** @param array<string,mixed> $metadata */
    public function __construct(
        private readonly string $invoiceUuid,
        private readonly int $amountCents,
        private readonly array $metadata = [],
    ) {
        parent::__construct();
    }

    public function auditAction(): string
    {
        return 'paid';
    }

    public function auditCategory(): string
    {
        return 'billing';
    }

    public function auditTarget(): array
    {
        return ['type' => 'invoice', 'uuid' => $this->invoiceUuid, 'label' => 'Invoice #' . $this->invoiceUuid];
    }

    public function auditMetadata(): array
    {
        return array_merge(['amount_cents' => $this->amountCents], $this->metadata);
    }
}

/** Bare event: relies entirely on the defaults trait (no target, no changes, no metadata). */
final class BareAuditableFixture extends BaseEvent implements AuditableEvent
{
    use AuditableEventDefaults;

    public function auditAction(): string
    {
        return 'exported';
    }

    public function auditCategory(): string
    {
        return 'data';
    }
}

/** Update event carrying field-level changes. */
final class EntryUpdatedFixture extends BaseEvent implements AuditableEvent
{
    use AuditableEventDefaults;

    /** @param array<string,array<string,mixed>> $changes */
    public function __construct(
        private readonly string $entryUuid,
        private readonly array $changes,
    ) {
        parent::__construct();
    }

    public function auditAction(): string
    {
        return 'updated';
    }

    public function auditCategory(): string
    {
        return 'content';
    }

    public function auditTarget(): array
    {
        return ['type' => 'content_entry', 'uuid' => $this->entryUuid];
    }

    public function auditChanges(): ?array
    {
        return $this->changes;
    }
}
