<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit\Events;

use Glueful\Bootstrap\ApplicationContext;
use Glueful\Events\EventSubscriberInterface;
use Glueful\Extensions\Aegis\Events\PermissionAssignedEvent;
use Glueful\Extensions\Aegis\Events\PermissionRevokedEvent;
use Glueful\Extensions\Aegis\Events\RoleAssignedEvent;
use Glueful\Extensions\Aegis\Events\RolePermissionAssignedEvent;
use Glueful\Extensions\Aegis\Events\RolePermissionRevokedEvent;
use Glueful\Extensions\Aegis\Events\RoleRevokedEvent;
use Glueful\Extensions\Audit\Services\AuditRecorder;
use Glueful\Extensions\Audit\Support\ActorResolver;
use Glueful\Extensions\Audit\Support\AuditEntry;
use Symfony\Component\HttpFoundation\Request;
use Throwable;

/**
 * RBAC domain-event audit subscriber (registered only when Aegis is present).
 *
 * Records semantic RBAC rows ("Michael assigned Admin to Jane") rather than
 * pivot-table noise. All rows are `category = rbac`.
 *
 * Target convention:
 *  - grants/revokes to a USER (Role and Permission events) → target_type = `user`,
 *    target_uuid = the user uuid; the role/permission uuid + looked-up slug/name
 *    go in `context`.
 *  - role↔permission links (RolePermission events) → target_type = `role`,
 *    target_uuid = the role uuid; the permission uuid + slug/name go in `context`.
 *
 * The event classes are referenced by ::class only (a compile-time string — no
 * autoload), so this file is safe to define even when Aegis is absent; the typed
 * handlers only load when an event actually fires (i.e. when Aegis is installed).
 * Label enrichment resolves the Aegis read repositories from the container
 * best-effort and never throws.
 */
final class AegisAuditSubscriber implements EventSubscriberInterface
{
    private const ROLE_REPOSITORY = 'Glueful\\Extensions\\Aegis\\Repositories\\RoleRepository';
    private const PERMISSION_REPOSITORY = 'Glueful\\Extensions\\Aegis\\Repositories\\PermissionRepository';

    private ?Request $request = null;
    private bool $requestResolved = false;

    public function __construct(
        private readonly AuditRecorder $recorder,
        private readonly ActorResolver $actorResolver,
        private readonly ApplicationContext $context,
    ) {
    }

    /**
     * @return array<string, string>
     */
    public static function getSubscribedEvents(): array
    {
        return [
            RoleAssignedEvent::class => 'onRoleAssigned',
            RoleRevokedEvent::class => 'onRoleRevoked',
            PermissionAssignedEvent::class => 'onPermissionAssigned',
            PermissionRevokedEvent::class => 'onPermissionRevoked',
            RolePermissionAssignedEvent::class => 'onRolePermissionAssigned',
            RolePermissionRevokedEvent::class => 'onRolePermissionRevoked',
        ];
    }

    public function withRequest(?Request $request): self
    {
        $this->request = $request;
        $this->requestResolved = true;

        return $this;
    }

    // ---- user ↔ role ----------------------------------------------------------

    public function onRoleAssigned(RoleAssignedEvent $event): void
    {
        $this->record($event, 'role_assigned', 'user', $event->userUuid, $this->roleContext(
            $event->roleUuid,
            $event->options,
        ));
    }

    public function onRoleRevoked(RoleRevokedEvent $event): void
    {
        $this->record($event, 'role_revoked', 'user', $event->userUuid, $this->roleContext(
            $event->roleUuid,
            [],
        ));
    }

    // ---- user ↔ permission ----------------------------------------------------

    public function onPermissionAssigned(PermissionAssignedEvent $event): void
    {
        $this->record($event, 'permission_assigned', 'user', $event->userUuid, $this->permissionContext(
            $event->permissionUuid,
            $event->options,
        ));
    }

    public function onPermissionRevoked(PermissionRevokedEvent $event): void
    {
        $this->record($event, 'permission_revoked', 'user', $event->userUuid, $this->permissionContext(
            $event->permissionUuid,
            [],
        ));
    }

    // ---- role ↔ permission ----------------------------------------------------

    public function onRolePermissionAssigned(RolePermissionAssignedEvent $event): void
    {
        $this->record($event, 'role_permission_assigned', 'role', $event->roleUuid, $this->permissionContext(
            $event->permissionUuid,
            $event->options,
        ));
    }

    public function onRolePermissionRevoked(RolePermissionRevokedEvent $event): void
    {
        $this->record($event, 'role_permission_revoked', 'role', $event->roleUuid, $this->permissionContext(
            $event->permissionUuid,
            [],
        ));
    }

    // ---- shared ---------------------------------------------------------------

    /**
     * @param array<string,mixed> $context the resolved "other side" + options
     */
    private function record(
        object $event,
        string $action,
        string $targetType,
        string $targetUuid,
        array $context,
    ): void {
        if (!$this->capturing()) {
            return;
        }

        $actor = $this->actorResolver->resolve($this->currentRequest());

        $context = array_filter(array_merge($context, [
            'ip' => $actor['ip'],
            'user_agent' => $actor['user_agent'],
            'request_id' => $actor['request_id'],
            'event_id' => method_exists($event, 'getEventId') ? $event->getEventId() : null,
        ]), static fn ($v): bool => $v !== null && $v !== []);

        try {
            $this->recorder->record(new AuditEntry(
                occurredAt: method_exists($event, 'getTimestamp')
                    ? $event->getTimestamp()
                    : microtime(true),
                action: $action,
                category: 'rbac',
                actorUuid: $actor['actor_uuid'],
                actorLabel: $actor['actor_label'],
                targetType: $targetType,
                targetUuid: $targetUuid,
                targetLabel: $this->targetLabel($targetType, $targetUuid),
                changes: null,
                context: $context,
            ));
        } catch (Throwable) {
            // Audit failures never break the audited operation.
        }
    }

    private function capturing(): bool
    {
        return (bool) config($this->context, 'audit.capture.rbac', true);
    }

    /**
     * Context for a role reference (the "other side" of a user grant).
     *
     * @param array<string,mixed> $options
     * @return array<string,mixed>
     */
    private function roleContext(string $roleUuid, array $options): array
    {
        $context = ['role_uuid' => $roleUuid];

        $label = $this->lookupLabel(self::ROLE_REPOSITORY, 'findRoleByUuid', $roleUuid);
        if ($label !== null) {
            $context['role_slug'] = $label['slug'];
            $context['role_name'] = $label['name'];
        }

        return array_merge($context, $this->optionContext($options));
    }

    /**
     * Context for a permission reference.
     *
     * @param array<string,mixed> $options
     * @return array<string,mixed>
     */
    private function permissionContext(string $permissionUuid, array $options): array
    {
        $context = ['permission_uuid' => $permissionUuid];

        $label = $this->lookupLabel(self::PERMISSION_REPOSITORY, 'findPermissionByUuid', $permissionUuid);
        if ($label !== null) {
            $context['permission_slug'] = $label['slug'];
            $context['permission_name'] = $label['name'];
        }

        return array_merge($context, $this->optionContext($options));
    }

    /**
     * Carry through the write options the audit row cares about.
     *
     * @param array<string,mixed> $options
     * @return array<string,mixed>
     */
    private function optionContext(array $options): array
    {
        $context = [];
        foreach (['resource_filter', 'expires_at', 'constraints', 'granted_by'] as $key) {
            if (isset($options[$key]) && $options[$key] !== null) {
                $context[$key] = $options[$key];
            }
        }

        return $context;
    }

    /**
     * Resolve the label of the modified target (the user/role being acted on).
     */
    private function targetLabel(string $targetType, string $targetUuid): ?string
    {
        if ($targetType === 'role') {
            $label = $this->lookupLabel(self::ROLE_REPOSITORY, 'findRoleByUuid', $targetUuid);
            return $label['name'] ?? null;
        }

        // target_type === 'user' — user labels live in another package; omit.
        return null;
    }

    /**
     * Best-effort slug/name lookup via an Aegis read repository resolved from the
     * container. Null-safe: missing repo, missing row, or any error → null.
     *
     * @return array{slug:string,name:string}|null
     */
    private function lookupLabel(string $repositoryClass, string $method, string $uuid): ?array
    {
        if ($uuid === '') {
            return null;
        }

        try {
            if (!$this->context->hasContainer()) {
                return null;
            }
            $container = $this->context->getContainer();
            if (!$container->has($repositoryClass)) {
                return null;
            }
            $repository = $container->get($repositoryClass);
            if (!is_object($repository) || !method_exists($repository, $method)) {
                return null;
            }

            /** @var object|null $model */
            $model = $repository->{$method}($uuid);
            if (
                !is_object($model)
                || !method_exists($model, 'getSlug')
                || !method_exists($model, 'getName')
            ) {
                return null;
            }

            $slug = $model->getSlug();
            $name = $model->getName();

            return [
                'slug' => is_scalar($slug) ? (string) $slug : '',
                'name' => is_scalar($name) ? (string) $name : '',
            ];
        } catch (Throwable) {
            return null;
        }
    }

    private function currentRequest(): ?Request
    {
        if ($this->requestResolved) {
            return $this->request;
        }

        $this->requestResolved = true;
        $this->request = null;

        try {
            if ($this->context->hasContainer()) {
                $container = $this->context->getContainer();
                if ($container->has(Request::class)) {
                    $resolved = $container->get(Request::class);
                    if ($resolved instanceof Request) {
                        $this->request = $resolved;
                    }
                }
            }
        } catch (Throwable) {
            $this->request = null;
        }

        return $this->request;
    }
}
