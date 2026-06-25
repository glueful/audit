<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Tests\Events;

use Glueful\Database\Connection;
use Glueful\Extensions\Aegis\Events\PermissionAssignedEvent;
use Glueful\Extensions\Aegis\Events\RoleAssignedEvent;
use Glueful\Extensions\Aegis\Events\RolePermissionAssignedEvent;
use Glueful\Extensions\Aegis\Events\RolePermissionRevokedEvent;
use Glueful\Extensions\Aegis\Events\RoleRevokedEvent;
use Glueful\Extensions\Audit\Events\AegisAuditSubscriber;
use Glueful\Extensions\Audit\Services\AuditRecorder;
use Glueful\Extensions\Audit\Support\ActorResolver;
use Glueful\Extensions\Audit\Tests\Support\AuditTestCase;
use Psr\Container\ContainerInterface;
use Psr\Container\NotFoundExceptionInterface;

final class AegisAuditSubscriberTest extends AuditTestCase
{
    public const ROLE_REPO = 'Glueful\\Extensions\\Aegis\\Repositories\\RoleRepository';
    public const PERMISSION_REPO = 'Glueful\\Extensions\\Aegis\\Repositories\\PermissionRepository';

    protected function setUp(): void
    {
        parent::setUp();
        $this->runMigration();
        $this->context->mergeConfigDefaults('audit', [
            'capture' => ['rbac' => true],
            'redact_fields' => ['password', 'secret', 'api_key', '*_token'],
        ]);
    }

    private function subscriber(): AegisAuditSubscriber
    {
        $subscriber = new AegisAuditSubscriber(
            new AuditRecorder($this->context),
            new ActorResolver(),
            $this->context,
        );

        return $subscriber->withRequest(null);
    }

    /**
     * Install a container that provides the Connection (for the recorder's db())
     * and fake Aegis read repositories for label enrichment.
     */
    private function installRbacContainer(): void
    {
        $role = new class {
            public function findRoleByUuid(string $uuid): ?object
            {
                if ($uuid !== 'r1') {
                    return null;
                }
                return new class {
                    public function getSlug(): string
                    {
                        return 'admin';
                    }
                    public function getName(): string
                    {
                        return 'Administrator';
                    }
                };
            }
        };

        $permission = new class {
            public function findPermissionByUuid(string $uuid): ?object
            {
                if ($uuid !== 'p1') {
                    return null;
                }
                return new class {
                    public function getSlug(): string
                    {
                        return 'posts.write';
                    }
                    public function getName(): string
                    {
                        return 'Write Posts';
                    }
                };
            }
        };

        $connection = $this->connection;

        $container = new class ($connection, $role, $permission) implements ContainerInterface {
            public function __construct(
                private Connection $connection,
                private object $roleRepo,
                private object $permissionRepo,
            ) {
            }

            public function get(string $id): mixed
            {
                if ($id === Connection::class || $id === 'database') {
                    return $this->connection;
                }
                if ($id === AegisAuditSubscriberTest::ROLE_REPO) {
                    return $this->roleRepo;
                }
                if ($id === AegisAuditSubscriberTest::PERMISSION_REPO) {
                    return $this->permissionRepo;
                }
                throw new class () extends \RuntimeException implements NotFoundExceptionInterface {
                };
            }

            public function has(string $id): bool
            {
                return in_array($id, [
                    Connection::class,
                    'database',
                    AegisAuditSubscriberTest::ROLE_REPO,
                    AegisAuditSubscriberTest::PERMISSION_REPO,
                ], true);
            }
        };

        $this->context->setContainer($container);
    }

    public function testRoleAssignedProducesUserTargetedRowWithRoleContext(): void
    {
        $this->installRbacContainer();

        $this->subscriber()->onRoleAssigned(new RoleAssignedEvent('user-1', 'r1', [
            'granted_by' => 'admin-uuid',
            'expires_at' => '2027-01-01 00:00:00',
        ]));

        $row = $this->onlyRow();
        self::assertSame('role_assigned', $row['action']);
        self::assertSame('rbac', $row['category']);
        self::assertSame('user', $row['target_type']);
        self::assertSame('user-1', $row['target_uuid']);

        $context = json_decode((string) $row['context'], true);
        self::assertSame('r1', $context['role_uuid']);
        self::assertSame('admin', $context['role_slug']);
        self::assertSame('Administrator', $context['role_name']);
        self::assertSame('admin-uuid', $context['granted_by']);
        self::assertSame('2027-01-01 00:00:00', $context['expires_at']);
        // System actor (no request).
        self::assertSame('system', $row['actor_label']);
    }

    public function testRoleRevokedRow(): void
    {
        $this->installRbacContainer();

        $this->subscriber()->onRoleRevoked(new RoleRevokedEvent('user-1', 'r1'));

        $row = $this->onlyRow();
        self::assertSame('role_revoked', $row['action']);
        self::assertSame('user', $row['target_type']);
        self::assertSame('user-1', $row['target_uuid']);
        $context = json_decode((string) $row['context'], true);
        self::assertSame('r1', $context['role_uuid']);
        self::assertSame('admin', $context['role_slug']);
    }

    public function testPermissionAssignedCarriesResourceFilter(): void
    {
        $this->installRbacContainer();

        $this->subscriber()->onPermissionAssigned(new PermissionAssignedEvent('user-1', 'p1', [
            'resource_filter' => ['resource' => 'posts/42'],
        ]));

        $row = $this->onlyRow();
        self::assertSame('permission_assigned', $row['action']);
        self::assertSame('user', $row['target_type']);
        self::assertSame('user-1', $row['target_uuid']);
        $context = json_decode((string) $row['context'], true);
        self::assertSame('p1', $context['permission_uuid']);
        self::assertSame('posts.write', $context['permission_slug']);
        self::assertSame(['resource' => 'posts/42'], $context['resource_filter']);
    }

    public function testRolePermissionAssignedTargetsRole(): void
    {
        $this->installRbacContainer();

        $this->subscriber()->onRolePermissionAssigned(new RolePermissionAssignedEvent('r1', 'p1'));

        $row = $this->onlyRow();
        self::assertSame('role_permission_assigned', $row['action']);
        self::assertSame('role', $row['target_type']);
        self::assertSame('r1', $row['target_uuid']);
        self::assertSame('Administrator', $row['target_label']);
        $context = json_decode((string) $row['context'], true);
        self::assertSame('p1', $context['permission_uuid']);
        self::assertSame('posts.write', $context['permission_slug']);
    }

    public function testRolePermissionRevokedRow(): void
    {
        $this->installRbacContainer();

        $this->subscriber()->onRolePermissionRevoked(new RolePermissionRevokedEvent('r1', 'p1'));

        $row = $this->onlyRow();
        self::assertSame('role_permission_revoked', $row['action']);
        self::assertSame('role', $row['target_type']);
        self::assertSame('r1', $row['target_uuid']);
    }

    public function testEnrichmentIsNullSafeWhenRepoMissing(): void
    {
        // No RBAC container installed → only the harness container (no aegis repos).
        // The row is still written; labels are simply omitted.
        $this->subscriber()->onRoleAssigned(new RoleAssignedEvent('user-1', 'r-unknown'));

        $row = $this->onlyRow();
        self::assertSame('role_assigned', $row['action']);
        $context = json_decode((string) $row['context'], true);
        self::assertSame('r-unknown', $context['role_uuid']);
        self::assertArrayNotHasKey('role_slug', $context);
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
