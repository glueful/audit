<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Tests\Events;

use Glueful\Auth\Contracts\UserProviderInterface;
use Glueful\Auth\UserIdentity;
use Glueful\Events\Auth\AuthenticationFailedEvent;
use Glueful\Events\Auth\SessionCreatedEvent;
use Glueful\Events\Auth\SessionDestroyedEvent;
use Glueful\Events\Database\EntityCreatedEvent;
use Glueful\Events\Database\EntityDeletedEvent;
use Glueful\Events\Database\EntityUpdatedEvent;
use Glueful\Extensions\Audit\Events\AuditSubscriber;
use Glueful\Extensions\Audit\Services\AuditRecorder;
use Glueful\Extensions\Audit\Support\ActorResolver;
use Glueful\Extensions\Audit\Tests\Support\AuditTestCase;
use Symfony\Component\HttpFoundation\Request;

final class AuditSubscriberTest extends AuditTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->runMigration();
        $this->context->mergeConfigDefaults('audit', [
            'enabled' => true,
            'capture' => ['entities' => true, 'auth' => true, 'security' => true, 'rbac' => true],
            'ignore_tables' => ['audit_logs', 'auth_sessions', 'cache'],
            'rbac_pivot_tables' => ['user_roles', 'user_permissions', 'role_permissions'],
            'rbac_semantic_active' => false,
            'category_map' => [],
            'redact_fields' => ['password', 'password_hash', 'secret', 'api_key', '*_token'],
        ]);
    }

    private function subscriber(): AuditSubscriber
    {
        $subscriber = new AuditSubscriber(
            new AuditRecorder($this->context),
            new ActorResolver(),
            $this->context,
        );

        // No active request → system actor; explicit to keep tests hermetic.
        return $subscriber->withRequest(null);
    }

    // ---- entity events --------------------------------------------------------

    public function testEntityCreatedProducesCreatedRow(): void
    {
        $this->subscriber()->onEntityCreated(new EntityCreatedEvent(
            ['uuid' => 'u1', 'name' => 'Jane', 'email' => 'jane@example.com'],
            'users',
        ));

        $row = $this->onlyRow();
        self::assertSame('created', $row['action']);
        self::assertSame('user', $row['category']);
        self::assertSame('user', $row['target_type']);
        self::assertSame('u1', $row['target_uuid']);
        self::assertSame('Jane', $row['target_label']);
        self::assertNull($row['changes']);
    }

    public function testEntityRowRecordsTheActorFromTheRequest(): void
    {
        $request = \Symfony\Component\HttpFoundation\Request::create('/x', 'POST');
        // The always-present post-auth `'user'` array (not the optional auth.user enricher).
        $request->attributes->set('user', ['uuid' => 'admin-1', 'email' => 'admin@example.com']);

        $subscriber = (new AuditSubscriber(new AuditRecorder($this->context), new ActorResolver(), $this->context))
            ->withRequest($request);
        $subscriber->onEntityCreated(new EntityCreatedEvent(['uuid' => 'u2', 'name' => 'Bob'], 'users'));

        $row = $this->onlyRow();
        self::assertSame('admin-1', $row['actor_uuid']);
        self::assertSame('admin@example.com', $row['actor_label']);
    }

    public function testActorLabelResolvedFromUuidWhenRequestCarriesUuidOnly(): void
    {
        // A request principal that carries only the actor uuid (no email/username) — so request
        // resolution alone would label the row with the bare uuid. With a user provider bound, the
        // subscriber resolves a human-readable label from the uuid.
        $this->userProvider = new class implements UserProviderInterface {
            public function findByUuid(string $uuid): ?UserIdentity
            {
                return $uuid === 'admin-3'
                    ? new UserIdentity('admin-3', [], [], [], 'admin3@example.com', 'admin3')
                    : null;
            }

            public function findByLogin(string $identifier): ?UserIdentity
            {
                return null;
            }

            public function verifyCredentials(string $identifier, string $password): ?UserIdentity
            {
                return null;
            }
        };

        $request = Request::create('/x', 'POST');
        $request->attributes->set('user', ['uuid' => 'admin-3']); // uuid only — no email/username
        $subscriber = (new AuditSubscriber(new AuditRecorder($this->context), new ActorResolver(), $this->context))
            ->withRequest($request);
        $subscriber->onEntityCreated(new EntityCreatedEvent(['uuid' => 'u3', 'name' => 'Carol'], 'users'));

        $row = $this->onlyRow();
        self::assertSame('admin-3', $row['actor_uuid']);
        self::assertSame('admin3@example.com', $row['actor_label']);
    }

    public function testEntityFallsBackToRowCreatedByWhenNoRequestActor(): void
    {
        // No resolvable request (system) but the row records who created it — e.g. a blob upload
        // whose EntityCreatedEvent fires outside a request scope. The actor must come from
        // created_by instead of defaulting to "system".
        $this->subscriber()->onEntityCreated(new EntityCreatedEvent(
            ['uuid' => 'b1', 'name' => 'photo.jpg', 'created_by' => 'admin-1'],
            'blobs',
        ));

        $row = $this->onlyRow();
        self::assertSame('admin-1', $row['actor_uuid']);
        // No UserProviderInterface bound in the test container → label falls back to the uuid.
        self::assertSame('admin-1', $row['actor_label']);
    }

    public function testEntityDeletedFallsBackToRowCreatedBy(): void
    {
        $this->subscriber()->onEntityDeleted(new EntityDeletedEvent(
            ['uuid' => 'b2', 'name' => 'gone.jpg', 'created_by' => 'admin-2'],
            'blobs',
        ));

        $row = $this->onlyRow();
        self::assertSame('deleted', $row['action']);
        self::assertSame('admin-2', $row['actor_uuid']);
        self::assertSame('admin-2', $row['actor_label']);
    }

    public function testEntityUpdatedCarriesRedactedChanges(): void
    {
        $this->subscriber()->onEntityUpdated(new EntityUpdatedEvent(
            ['uuid' => 'u1', 'name' => 'Jane'],
            'users',
            ['name' => ['from' => 'Jan', 'to' => 'Jane'], 'password' => 'new-hash'],
        ));

        $row = $this->onlyRow();
        self::assertSame('updated', $row['action']);
        $changes = json_decode((string) $row['changes'], true);
        self::assertSame(['from' => 'Jan', 'to' => 'Jane'], $changes['name']);
        // password shaped to {to: ...} then redacted by the recorder.
        self::assertSame('[redacted]', $changes['password']);
    }

    public function testEntityDeletedHasNullChangesAndLabelFromPreDeleteRecord(): void
    {
        $this->subscriber()->onEntityDeleted(new EntityDeletedEvent(
            ['uuid' => 'u9', 'name' => 'Gone User'],
            'users',
        ));

        $row = $this->onlyRow();
        self::assertSame('deleted', $row['action']);
        self::assertSame('u9', $row['target_uuid']);
        self::assertSame('Gone User', $row['target_label']);
        self::assertNull($row['changes']);
    }

    public function testIgnoredTableProducesNoRow(): void
    {
        $this->subscriber()->onEntityCreated(new EntityCreatedEvent(['uuid' => 's1'], 'auth_sessions'));
        self::assertSame([], $this->rows());
    }

    public function testAuditLogsWriteIsNeverAuditedRecursionGuard(): void
    {
        $this->subscriber()->onEntityCreated(new EntityCreatedEvent(['uuid' => 'a1'], 'audit_logs'));
        self::assertSame([], $this->rows());
    }

    public function testCaptureToggleOffNoOps(): void
    {
        $this->context->mergeConfigDefaults('audit', ['capture' => ['entities' => false]]);
        $this->subscriber()->onEntityCreated(new EntityCreatedEvent(['uuid' => 'u1', 'name' => 'X'], 'users'));
        self::assertSame([], $this->rows());
    }

    // ---- conditional pivot suppression (the point) ----------------------------

    public function testRbacPivotSuppressedWhenSemanticActive(): void
    {
        $this->context->mergeConfigDefaults('audit', ['rbac_semantic_active' => true]);

        $this->subscriber()->onEntityCreated(new EntityCreatedEvent(
            ['uuid' => 'rp1', 'role_uuid' => 'r1', 'permission_uuid' => 'p1'],
            'role_permissions',
        ));

        self::assertSame([], $this->rows(), 'pivot must be suppressed when semantic subscriber active');
    }

    public function testRbacPivotRecordedGenericallyWhenSemanticInactive(): void
    {
        // rbac_semantic_active defaults false here.
        $this->subscriber()->onEntityCreated(new EntityCreatedEvent(
            ['uuid' => 'rp1', 'role_uuid' => 'r1', 'permission_uuid' => 'p1'],
            'role_permissions',
        ));

        $row = $this->onlyRow();
        self::assertSame('created', $row['action']);
        self::assertSame('rbac', $row['category']);
        self::assertSame('role_permissions', $row['target_type']);
    }

    // ---- auth events: token allow-list (non-negotiable) -----------------------

    public function testLoginRowContainsNoTokenValues(): void
    {
        $this->subscriber()->onSessionCreated(new SessionCreatedEvent(
            ['uuid' => 'u1', 'username' => 'jane'],
            ['access_token' => 'SECRET-ACCESS-TOKEN', 'refresh_token' => 'SECRET-REFRESH-TOKEN'],
        ));

        $row = $this->onlyRow();
        self::assertSame('login', $row['action']);
        self::assertSame('auth', $row['category']);
        self::assertSame('u1', $row['target_uuid']);
        self::assertSame('jane', $row['target_label']);

        $serialized = $this->serializedRow($row);
        self::assertStringNotContainsString('SECRET-ACCESS-TOKEN', $serialized);
        self::assertStringNotContainsString('SECRET-REFRESH-TOKEN', $serialized);
    }

    public function testLogoutRowContainsNoTokenValues(): void
    {
        $this->subscriber()->onSessionDestroyed(new SessionDestroyedEvent(
            'SECRET-ACCESS-TOKEN-LOGOUT',
            'u1',
            'logout',
        ));

        $row = $this->onlyRow();
        self::assertSame('logout', $row['action']);
        $changes = json_decode((string) $row['changes'], true);
        self::assertSame(['to' => 'logout'], $changes['reason']);

        $serialized = $this->serializedRow($row);
        self::assertStringNotContainsString('SECRET-ACCESS-TOKEN-LOGOUT', $serialized);
    }

    public function testLogoutRecordsTheActorLabelFromTheRequest(): void
    {
        // SessionDestroyedEvent carries no username, so the label comes from the resolved request
        // actor — logout no longer records just the uuid (login records the username).
        $request = \Symfony\Component\HttpFoundation\Request::create('/x', 'POST');
        $request->attributes->set('user', ['uuid' => 'u1', 'email' => 'jane@example.com']);
        $subscriber = (new AuditSubscriber(new AuditRecorder($this->context), new ActorResolver(), $this->context))
            ->withRequest($request);

        $subscriber->onSessionDestroyed(new SessionDestroyedEvent('TOKEN', 'u1', 'logout'));

        $row = $this->onlyRow();
        self::assertSame('u1', $row['actor_uuid']);
        self::assertSame('jane@example.com', $row['actor_label']);
    }

    public function testFailedLoginRecordsReason(): void
    {
        $this->subscriber()->onAuthFailed(new AuthenticationFailedEvent(
            'jane@example.com',
            'invalid_credentials',
            '203.0.113.7',
        ));

        $row = $this->onlyRow();
        self::assertSame('login_failed', $row['action']);
        self::assertSame('jane@example.com', $row['target_label']);
        $changes = json_decode((string) $row['changes'], true);
        self::assertSame(['to' => 'invalid_credentials'], $changes['reason']);
    }

    // ---- helpers --------------------------------------------------------------

    private function serializedRow(array $row): string
    {
        return implode('|', array_map(static fn ($v): string => (string) $v, $row));
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
