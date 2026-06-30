<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Tests\Support;

use Glueful\Auth\Contracts\UserProviderInterface;
use Glueful\Auth\UserIdentity;
use Glueful\Bootstrap\ApplicationContext;
use Glueful\Extensions\Audit\Support\ActorResolver;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Symfony\Component\HttpFoundation\Request;

final class ActorResolverTest extends TestCase
{
    /** A context with no container — store lookups are skipped (label falls back to the uuid). */
    private function ctx(): ApplicationContext
    {
        return new ApplicationContext('/tmp');
    }

    public function testResolvesSystemActorWithoutRequest(): void
    {
        $resolved = (new ActorResolver($this->ctx()))->resolve(null);

        self::assertNull($resolved['actor_uuid']);
        self::assertSame('system', $resolved['actor_label']);
        self::assertNull($resolved['ip']);
        self::assertNull($resolved['user_agent']);
        self::assertNull($resolved['request_id']);
    }

    public function testResolvesSystemActorWhenRequestHasNoPrincipal(): void
    {
        $request = Request::create('/x', 'GET');

        $resolved = (new ActorResolver($this->ctx()))->resolve($request);

        self::assertNull($resolved['actor_uuid']);
        self::assertSame('system', $resolved['actor_label']);
    }

    public function testResolvesPrincipalFromAuthUserAttribute(): void
    {
        $request = Request::create('/x', 'GET', [], [], [], [
            'REMOTE_ADDR' => '203.0.113.7',
            'HTTP_USER_AGENT' => 'TestAgent/1.0',
        ]);
        $request->headers->set('X-Request-Id', 'req-123');

        $identity = new UserIdentity(
            uuid: 'user-uuid-9',
            email: 'jane@example.com',
            username: 'jane',
        );
        $request->attributes->set('auth.user', $identity);

        $resolved = (new ActorResolver($this->ctx()))->resolve($request);

        self::assertSame('user-uuid-9', $resolved['actor_uuid']);
        self::assertSame('jane@example.com', $resolved['actor_label']);
        self::assertSame('203.0.113.7', $resolved['ip']);
        self::assertSame('TestAgent/1.0', $resolved['user_agent']);
        self::assertSame('req-123', $resolved['request_id']);
    }

    public function testFallsBackToUsernameThenUuidForLabel(): void
    {
        $request = Request::create('/x', 'GET');
        $request->attributes->set('auth.user', new UserIdentity(uuid: 'only-uuid'));

        // No container → no store lookup → the uuid is the last-resort label.
        $resolved = (new ActorResolver($this->ctx()))->resolve($request);

        self::assertSame('only-uuid', $resolved['actor_uuid']);
        self::assertSame('only-uuid', $resolved['actor_label']);
    }

    /**
     * The `auth.user` UserIdentity is set by an OPTIONAL enricher most apps don't
     * register; AuthMiddleware ALWAYS sets the `'user'` array. Resolving must fall
     * back to it, else every authenticated action records as `system`.
     */
    public function testResolvesPrincipalFromUserArrayAttributeFallback(): void
    {
        $request = Request::create('/x', 'GET');
        $request->attributes->set('user', [
            'uuid' => 'arr-uuid-1',
            'email' => 'arr@example.com',
            'roles' => ['administrator'],
        ]);

        $resolved = (new ActorResolver($this->ctx()))->resolve($request);

        self::assertSame('arr-uuid-1', $resolved['actor_uuid']);
        self::assertSame('arr@example.com', $resolved['actor_label']);
    }

    public function testUserArrayFallbackLabelPrefersUsernameThenUuid(): void
    {
        $request = Request::create('/x', 'GET');
        $request->attributes->set('user', ['uuid' => 'arr-uuid-2', 'username' => 'bob']);
        self::assertSame('bob', (new ActorResolver($this->ctx()))->resolve($request)['actor_label']);

        $bare = Request::create('/x', 'GET');
        $bare->attributes->set('user', ['uuid' => 'arr-uuid-3']);
        self::assertSame('arr-uuid-3', (new ActorResolver($this->ctx()))->resolve($bare)['actor_label']);
    }

    /**
     * The JWT principal carries only the uuid (no email/username). When the `'user'` array has just
     * a uuid, the label is resolved from the user store instead of degrading to the raw uuid.
     */
    public function testResolvesLabelFromUserStoreWhenPrincipalHasUuidOnly(): void
    {
        $provider = $this->createMock(UserProviderInterface::class);
        $provider->method('findByUuid')
            ->willReturn(new UserIdentity(uuid: 'jwt-uuid', email: 'looked-up@example.com'));

        $container = $this->createMock(ContainerInterface::class);
        $container->method('has')
            ->willReturnCallback(static fn (string $id): bool => $id === UserProviderInterface::class);
        $container->method('get')->willReturn($provider);

        $context = new ApplicationContext('/tmp');
        $context->setContainer($container);

        $request = Request::create('/x', 'GET');
        $request->attributes->set('user', ['uuid' => 'jwt-uuid']); // uuid only, as JWT auth produces

        $resolved = (new ActorResolver($context))->resolve($request);

        self::assertSame('jwt-uuid', $resolved['actor_uuid']);
        self::assertSame('looked-up@example.com', $resolved['actor_label']);
    }
}
