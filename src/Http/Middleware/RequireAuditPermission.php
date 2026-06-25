<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Http\Middleware;

use Glueful\Auth\UserIdentity;
use Glueful\Bootstrap\ApplicationContext;
use Glueful\Http\Response;
use Glueful\Permissions\PermissionManager;
use Glueful\Routing\RouteMiddleware;
use Symfony\Component\HttpFoundation\Request;

/**
 * Gate the audit read API on a permission (default `audit.view`) for the `audit`
 * resource. Reads the post-auth principal and checks it via PermissionManager::can(),
 * returning 403 otherwise.
 *
 * IMPORTANT: it reads the always-present `'user'` array attribute (set by
 * AuthMiddleware) as the primary source, only preferring the richer `auth.user`
 * {@see UserIdentity} when the OPTIONAL enricher middleware is registered. Reading
 * `auth.user` alone would 403 every authenticated request in apps (Lemma,
 * api-skeleton) that don't register that enricher — shutting the whole read API.
 */
final class RequireAuditPermission implements RouteMiddleware
{
    public function __construct(private ApplicationContext $context)
    {
    }

    public function handle(Request $request, callable $next, mixed ...$params): mixed
    {
        $permission = isset($params[0]) && is_string($params[0]) ? trim($params[0]) : '';
        if ($permission === '') {
            return $this->forbidden();
        }

        // Prefer the richer auth.user (optional enricher); fall back to the always-set
        // 'user' array so we don't fail-closed where the enricher isn't registered.
        $user = $request->attributes->get('auth.user');
        if ($user instanceof UserIdentity) {
            $actorUuid = $user->id();
            $roles = $user->roles();
            $scopes = $user->scopes();
        } else {
            $raw = $request->attributes->get('user');
            if (!is_array($raw) || !isset($raw['uuid']) || !is_string($raw['uuid']) || $raw['uuid'] === '') {
                return $this->forbidden();
            }
            $actorUuid = $raw['uuid'];
            $roles = is_array($raw['roles'] ?? null) ? $raw['roles'] : [];
            $scopes = is_array($raw['scopes'] ?? null) ? $raw['scopes'] : [];
        }

        $manager = $this->permissionManager();
        if ($manager === null) {
            return $this->forbidden();
        }

        $context = [
            'roles' => $roles,
            'scopes' => $scopes,
            'route_params' => (array) $request->attributes->get('route.params'),
            'jwt_claims' => (array) $request->attributes->get('jwt.claims'),
        ];

        if (!$manager->can($actorUuid, $permission, 'audit', $context)) {
            return $this->forbidden();
        }

        return $next($request);
    }

    private function permissionManager(): ?PermissionManager
    {
        $container = $this->context->getContainer();
        foreach ([PermissionManager::class, 'permission.manager'] as $id) {
            try {
                if ($container->has($id)) {
                    $manager = $container->get($id);
                    if ($manager instanceof PermissionManager) {
                        return $manager;
                    }
                }
            } catch (\Throwable) {
                continue;
            }
        }

        return null;
    }

    private function forbidden(): Response
    {
        return Response::error('Forbidden', Response::HTTP_FORBIDDEN, [
            'code' => 'FORBIDDEN',
        ]);
    }
}
