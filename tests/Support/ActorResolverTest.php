<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Tests\Support;

use Glueful\Auth\UserIdentity;
use Glueful\Extensions\Audit\Support\ActorResolver;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

final class ActorResolverTest extends TestCase
{
    public function testResolvesSystemActorWithoutRequest(): void
    {
        $resolved = (new ActorResolver())->resolve(null);

        self::assertNull($resolved['actor_uuid']);
        self::assertSame('system', $resolved['actor_label']);
        self::assertNull($resolved['ip']);
        self::assertNull($resolved['user_agent']);
        self::assertNull($resolved['request_id']);
    }

    public function testResolvesSystemActorWhenRequestHasNoPrincipal(): void
    {
        $request = Request::create('/x', 'GET');

        $resolved = (new ActorResolver())->resolve($request);

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

        $resolved = (new ActorResolver())->resolve($request);

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

        $resolved = (new ActorResolver())->resolve($request);

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

        $resolved = (new ActorResolver())->resolve($request);

        self::assertSame('arr-uuid-1', $resolved['actor_uuid']);
        self::assertSame('arr@example.com', $resolved['actor_label']);
    }

    public function testUserArrayFallbackLabelPrefersUsernameThenUuid(): void
    {
        $request = Request::create('/x', 'GET');
        $request->attributes->set('user', ['uuid' => 'arr-uuid-2', 'username' => 'bob']);
        self::assertSame('bob', (new ActorResolver())->resolve($request)['actor_label']);

        $bare = Request::create('/x', 'GET');
        $bare->attributes->set('user', ['uuid' => 'arr-uuid-3']);
        self::assertSame('arr-uuid-3', (new ActorResolver())->resolve($bare)['actor_label']);
    }
}
