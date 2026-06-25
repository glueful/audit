<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Tests;

use Glueful\Bootstrap\ApplicationContext;
use Glueful\Database\Connection;
use Glueful\Events\Database\EntityCreatedEvent;
use Glueful\Events\EventDispatcher;
use Glueful\Events\EventService;
use Glueful\Events\ListenerProvider;
use Glueful\Extensions\Aegis\Events\RoleAssignedEvent;
use Glueful\Extensions\Audit\AuditServiceProvider;
use Glueful\Extensions\Audit\Database\Migrations\CreateAuditLogsTable;
use Glueful\Extensions\Audit\Events\AegisAuditSubscriber;
use Glueful\Extensions\Audit\Events\AuditSubscriber;
use Glueful\Extensions\Audit\Services\AuditRecorder;
use Glueful\Extensions\Audit\Support\ActorResolver;
use Glueful\Repository\BaseRepository;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Psr\Container\NotFoundExceptionInterface;

/**
 * Boot/wiring integration test for AuditServiceProvider.
 *
 * Boots the provider against a real EventService + SQLite Connection wired through a
 * test container, then asserts the two boot branches:
 *
 *  - Aegis present (capture.rbac=true): rbac_semantic_active resolves true, the
 *    AegisAuditSubscriber is subscribed, and a generic role_permissions
 *    EntityCreatedEvent is suppressed (no fallback row).
 *  - "Aegis absent" proxy (capture.rbac=false): rbac_semantic_active is false, the
 *    AegisAuditSubscriber is NOT subscribed, the provider boots with no
 *    class-not-found, and a role_permissions EntityCreatedEvent falls back to one
 *    generic row.
 *
 * This test owns its own container/connection (it is not an AuditTestCase) so it can
 * inject an EventService whose subscribe() can resolve the subscriber instances.
 */
final class BootIntegrationTest extends TestCase
{
    private Connection $connection;
    private ApplicationContext $context;
    private EventService $events;
    private string $dbPath;

    protected function setUp(): void
    {
        parent::setUp();

        $this->dbPath = sys_get_temp_dir() . '/audit-boot-' . uniqid('', true) . '.sqlite';
        $this->context = ApplicationContext::forTesting(sys_get_temp_dir());

        // Real EventService over a fresh provider; the container resolves the audit
        // subscribers + Connection + EventService so subscribe()/dispatch() work.
        $provider = new ListenerProvider();
        $testCase = $this;
        $container = new class ($testCase) implements ContainerInterface {
            private ?EventService $events = null;

            public function __construct(private BootIntegrationTest $test)
            {
            }

            public function setEvents(EventService $events): void
            {
                $this->events = $events;
            }

            public function get(string $id): mixed
            {
                return $this->test->resolve($id, $this->events);
            }

            public function has(string $id): bool
            {
                return in_array($id, [
                    EventService::class,
                    Connection::class,
                    'database',
                    AuditSubscriber::class,
                    AegisAuditSubscriber::class,
                ], true);
            }
        };

        $this->events = new EventService(new EventDispatcher($provider), $provider, $container);
        $container->setEvents($this->events);
        $this->context->setContainer($container);

        $this->connection = new Connection([
            'engine' => 'sqlite',
            'sqlite' => ['primary' => $this->dbPath],
            'pooling' => ['enabled' => false],
        ], $this->context);

        $this->setSharedConnection($this->connection);
        (new CreateAuditLogsTable())->up($this->connection->getSchemaBuilder());

        // The provider's register() (mergeConfig) needs ApplicationContext in its $app
        // container, which this lightweight harness doesn't provide; merge the real audit
        // config defaults directly so rbac_pivot_tables / ignore_tables / capture are present.
        $config = require __DIR__ . '/../config/audit.php';
        $this->context->mergeConfigDefaults('audit', $config);
    }

    protected function tearDown(): void
    {
        $this->setSharedConnection(null);
        $this->resetConnectionInstances();
        if (is_file($this->dbPath)) {
            @unlink($this->dbPath);
        }
        parent::tearDown();
    }

    /**
     * Container resolver shared by the inline container above.
     */
    public function resolve(string $id, ?EventService $events): mixed
    {
        return match (true) {
            $id === EventService::class => $events,
            $id === Connection::class, $id === 'database' => $this->connection,
            $id === AuditSubscriber::class => new AuditSubscriber(
                new AuditRecorder($this->context),
                new ActorResolver(),
                $this->context,
            ),
            $id === AegisAuditSubscriber::class => new AegisAuditSubscriber(
                new AuditRecorder($this->context),
                new ActorResolver(),
                $this->context,
            ),
            default => throw new class () extends \RuntimeException implements NotFoundExceptionInterface {
            },
        };
    }

    public function testBootWithAegisPresentActivatesSemanticAndSuppressesPivot(): void
    {
        // capture.rbac defaults true; Aegis events exist in dev → semantic active.
        $this->boot();

        self::assertTrue(
            (bool) config($this->context, 'audit.rbac_semantic_active', false),
            'rbac_semantic_active should be true when Aegis is present and capture.rbac is on'
        );
        self::assertTrue(
            $this->events->hasListeners(RoleAssignedEvent::class),
            'AegisAuditSubscriber should be subscribed when semantic RBAC is active'
        );

        // A generic role_permissions entity event is suppressed (the semantic subscriber owns it).
        $this->events->dispatch(new EntityCreatedEvent(
            ['uuid' => 'rp1', 'role_uuid' => 'r1', 'permission_uuid' => 'p1'],
            'role_permissions',
        ));

        self::assertSame(0, $this->rowCount(), 'role_permissions generic row must be suppressed');
    }

    public function testBootWithCaptureRbacOffSkipsAegisAndFallsBackToGenericRow(): void
    {
        // The available proxy for "no Aegis": capture.rbac=false → rbac_semantic_active false.
        $this->context->mergeConfigDefaults('audit', ['capture' => ['rbac' => false]]);

        $this->boot();

        self::assertFalse(
            (bool) config($this->context, 'audit.rbac_semantic_active', true),
            'rbac_semantic_active should be false when capture.rbac is off'
        );
        self::assertFalse(
            $this->events->hasListeners(RoleAssignedEvent::class),
            'AegisAuditSubscriber must NOT be subscribed when semantic RBAC is inactive'
        );
        // AuditSubscriber is still active (core/auth/entity capture is unaffected).
        self::assertTrue($this->events->hasListeners(EntityCreatedEvent::class));

        // role_permissions now falls back to ONE generic row (not dropped).
        $this->events->dispatch(new EntityCreatedEvent(
            ['uuid' => 'rp1', 'role_uuid' => 'r1', 'permission_uuid' => 'p1'],
            'role_permissions',
        ));

        self::assertSame(1, $this->rowCount(), 'role_permissions should fall back to a generic row');
        $row = $this->firstRow();
        self::assertSame('created', $row['action']);
        self::assertSame('rbac', $row['category']);
        self::assertSame('role_permissions', $row['target_type']);
    }

    private function boot(): void
    {
        $provider = new AuditServiceProvider($this->context->getContainer());
        $provider->boot($this->context);
    }

    private function rowCount(): int
    {
        return (int) $this->connection->getPDO()
            ->query('SELECT COUNT(*) FROM audit_logs')
            ->fetchColumn();
    }

    /**
     * @return array<string,mixed>
     */
    private function firstRow(): array
    {
        /** @var array<string,mixed> $row */
        $row = $this->connection->getPDO()
            ->query('SELECT * FROM audit_logs ORDER BY id ASC LIMIT 1')
            ->fetch(\PDO::FETCH_ASSOC);

        return $row;
    }

    private function setSharedConnection(?Connection $connection): void
    {
        $property = new \ReflectionProperty(BaseRepository::class, 'sharedConnection');
        $property->setAccessible(true);
        $property->setValue(null, $connection);
    }

    private function resetConnectionInstances(): void
    {
        $property = new \ReflectionProperty(Connection::class, 'instances');
        $property->setAccessible(true);
        $property->setValue(null, []);
    }
}
