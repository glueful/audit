<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Support;

use Glueful\Auth\Contracts\UserProviderInterface;
use Glueful\Auth\UserIdentity;
use Glueful\Bootstrap\ApplicationContext;
use Symfony\Component\HttpFoundation\Request;
use Throwable;

/**
 * Resolves the current actor + request context for an audit row.
 *
 * Entity/domain events carry the *what* but not the *who*; the subscriber resolves
 * the authenticated principal from the current request at event time. We read the
 * post-auth `'user'` array attribute first — `AuthMiddleware` always sets it on an
 * authenticated request — and only then the richer `auth.user` {@see UserIdentity},
 * which is populated by an OPTIONAL enricher middleware that most apps (Lemma,
 * api-skeleton) do not register. Reading only `auth.user` would record every
 * authenticated action as `system`.
 *
 * The display label is best-effort, in order: the principal's own email/username when
 * present, otherwise a lookup from the user store by uuid, and finally the uuid itself.
 * The store lookup matters because the JWT principal carries only minimal claims (uuid,
 * no email/username) — without it, every JWT-authenticated action's label is the uuid.
 *
 * Best-effort and null-safe: when there is no request or no principal (CLI/system,
 * unauthenticated), the actor is `null` with the label `'system'`.
 */
final class ActorResolver
{
    public function __construct(private readonly ApplicationContext $context)
    {
    }

    /**
     * Resolve actor identity + request context.
     *
     * The subscriber supplies the current {@see Request} (entity/auth events do not
     * carry it). When none is available — CLI, queue worker, bootstrap — pass null
     * and the actor resolves to the system identity.
     *
     * @return array{
     *   actor_uuid: string|null,
     *   actor_label: string|null,
     *   ip: string|null,
     *   user_agent: string|null,
     *   request_id: string|null
     * }
     */
    public function resolve(?Request $request = null): array
    {
        if ($request === null) {
            return [
                'actor_uuid' => null,
                'actor_label' => 'system',
                'ip' => null,
                'user_agent' => null,
                'request_id' => null,
            ];
        }

        $actorUuid = null;
        $actorLabel = 'system';
        $user = $request->attributes->get('auth.user');
        if ($user instanceof UserIdentity) {
            $actorUuid = $user->uuid();
            $actorLabel = $user->email() ?? $user->username() ?? $this->labelForUuid($actorUuid) ?? $actorUuid;
        } else {
            // Fallback: the always-present post-auth `'user'` array (AuthMiddleware).
            $raw = $request->attributes->get('user');
            if (is_array($raw) && isset($raw['uuid']) && is_string($raw['uuid']) && $raw['uuid'] !== '') {
                $actorUuid = $raw['uuid'];
                $email = $raw['email'] ?? null;
                $username = $raw['username'] ?? null;
                $actorLabel = (is_string($email) && $email !== '') ? $email
                    : ((is_string($username) && $username !== '') ? $username
                    : ($this->labelForUuid($actorUuid) ?? $actorUuid));
            }
        }

        $requestId = $request->attributes->get('request.id')
            ?? $request->headers->get('X-Request-Id');

        return [
            'actor_uuid' => $actorUuid,
            'actor_label' => $actorLabel,
            'ip' => $request->getClientIp(),
            'user_agent' => $request->headers->get('User-Agent'),
            'request_id' => is_string($requestId) ? $requestId : null,
        ];
    }

    /**
     * Best-effort human label (email → username) for a user uuid, resolved from the user store via
     * {@see UserProviderInterface}. Returns null when there is no container, no provider, or no
     * match — callers fall back to the uuid. Never throws.
     */
    public function labelForUuid(string $uuid): ?string
    {
        if ($uuid === '') {
            return null;
        }

        try {
            if (!$this->context->hasContainer()) {
                return null;
            }
            $container = $this->context->getContainer();
            if (!$container->has(UserProviderInterface::class)) {
                return null;
            }
            $identity = $container->get(UserProviderInterface::class)->findByUuid($uuid);

            return $identity?->email() ?? $identity?->username();
        } catch (Throwable) {
            return null;
        }
    }
}
