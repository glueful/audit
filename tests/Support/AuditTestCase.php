<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Tests\Support;

use Glueful\Bootstrap\ApplicationContext;
use Glueful\Database\Connection;
use Glueful\Events\Contracts\BaseEvent;
use Glueful\Events\EventDispatcher;
use Glueful\Events\EventService;
use Glueful\Events\ListenerProvider;
use Glueful\Extensions\Audit\Database\Migrations\CreateAuditLogsTable;
use Glueful\Repository\BaseRepository;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Psr\Container\NotFoundExceptionInterface;

/**
 * Lightweight SQLite harness for the audit extension.
 *
 * Provides:
 *  - a temp-file SQLite {@see Connection} BOUND to a test {@see ApplicationContext} (so
 *    hasContext() === true and BaseRepository won't swap our in-test db for a default one);
 *  - an event-capture {@see EventService} behind a minimal PSR-11 container set on the
 *    context (so app($context, EventService::class) / dispatchEvent resolve to it);
 *  - $recordedEvents + helpers to assert dispatched domain events;
 *  - runMigration() to create audit_logs against the SQLite db;
 *  - tearDown that resets BaseRepository::$sharedConnection and Connection::$instances via
 *    reflection so distinct per-test databases never leak across cases.
 */
abstract class AuditTestCase extends TestCase
{
    protected Connection $connection;
    protected ApplicationContext $context;
    private string $dbPath;

    /**
     * Domain events captured during a test.
     *
     * @var list<BaseEvent>
     */
    protected array $recordedEvents = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->dbPath = sys_get_temp_dir() . '/audit-' . uniqid('', true) . '.sqlite';

        // Build the test context first, then bind the SQLite connection to it. BaseRepository
        // only replaces its shared connection when a context arrives and the current shared
        // connection hasContext() === false; binding the context here keeps repositories
        // constructed WITH this context using our in-test SQLite db.
        $this->context = ApplicationContext::forTesting(sys_get_temp_dir());
        $this->installEventCapture();

        $this->connection = new Connection([
            'engine' => 'sqlite',
            'sqlite' => ['primary' => $this->dbPath],
            'pooling' => ['enabled' => false],
        ], $this->context);

        // Make this the shared repository connection (BaseRepository::$sharedConnection).
        $this->setSharedConnection($this->connection);
    }

    protected function tearDown(): void
    {
        $this->setSharedConnection(null);
        $this->resetConnectionInstances();

        if (isset($this->dbPath) && is_file($this->dbPath)) {
            @unlink($this->dbPath);
        }

        parent::tearDown();
    }

    /**
     * Apply the audit_logs migration against the in-test SQLite database.
     */
    protected function runMigration(): void
    {
        (new CreateAuditLogsTable())->up($this->connection->getSchemaBuilder());
    }

    /**
     * Build a real EventService whose dispatcher records every BaseEvent into
     * $this->recordedEvents, exposed through a minimal PSR-11 container set on the test
     * context, plus the Connection so app($context, Connection::class) resolves it.
     */
    private function installEventCapture(): void
    {
        $this->recordedEvents = [];

        $provider = new ListenerProvider();
        // Catch-all: a listener on BaseEvent receives every subclass (the inheritance
        // resolver walks parents), so every dispatched domain event is recorded.
        $provider->addListener(BaseEvent::class, function (BaseEvent $event): void {
            $this->recordedEvents[] = $event;
        });
        $eventService = new EventService(new EventDispatcher($provider), $provider);

        // The connection is created AFTER this method runs, so resolve it lazily through a
        // closure that reads $this->connection at get()-time rather than capturing it now.
        $testCase = $this;
        $connectionResolver = static fn (): ?Connection => isset($testCase->connection)
            ? $testCase->connection
            : null;

        $container = new class ($eventService, $connectionResolver) implements ContainerInterface {
            /** @param \Closure():(Connection|null) $connectionResolver */
            public function __construct(
                private EventService $eventService,
                private \Closure $connectionResolver
            ) {
            }

            public function get(string $id): mixed
            {
                if ($id === EventService::class) {
                    return $this->eventService;
                }
                if ($id === Connection::class || $id === 'database') {
                    $connection = ($this->connectionResolver)();
                    if ($connection !== null) {
                        return $connection;
                    }
                }
                throw new class () extends \RuntimeException implements NotFoundExceptionInterface {
                };
            }

            public function has(string $id): bool
            {
                if ($id === EventService::class) {
                    return true;
                }

                return ($id === Connection::class || $id === 'database')
                    && ($this->connectionResolver)() !== null;
            }
        };

        $this->context->setContainer($container);
    }

    /**
     * Captured events of a given class.
     *
     * @template T of BaseEvent
     * @param class-string<T> $class
     * @return list<T>
     */
    protected function eventsOfType(string $class): array
    {
        return array_values(array_filter(
            $this->recordedEvents,
            static fn (BaseEvent $e): bool => $e instanceof $class
        ));
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
