<?php

declare(strict_types=1);

namespace Glueful\Extensions\Audit;

use Glueful\Bootstrap\ApplicationContext;
use Glueful\Database\Migrations\MigrationPriority;
use Glueful\Events\EventService;
use Glueful\Extensions\Audit\Contracts\AuditRecorderInterface;
use Glueful\Extensions\Audit\Events\AegisAuditSubscriber;
use Glueful\Extensions\Audit\Events\AuditSubscriber;
use Glueful\Extensions\Audit\Http\Controllers\AuditLogController;
use Glueful\Extensions\Audit\Http\Middleware\RequireAuditPermission;
use Glueful\Extensions\Audit\Repositories\AuditLogRepository;
use Glueful\Extensions\Audit\Services\AuditRecorder;
use Glueful\Extensions\Audit\Support\ActorResolver;
use Glueful\Extensions\Audit\Console\PruneAuditLogsCommand;
use Glueful\Extensions\ServiceProvider;
use Glueful\Permissions\Catalog\Permission;

final class AuditServiceProvider extends ServiceProvider
{
    private static ?string $cachedVersion = null;

    /**
     * Reads the extension version from composer.json's extra.glueful.version (cached).
     */
    public static function composerVersion(): string
    {
        if (self::$cachedVersion === null) {
            $raw = file_get_contents(__DIR__ . '/../composer.json');
            $composer = is_string($raw) ? json_decode($raw, true) : null;
            $version = is_array($composer) ? ($composer['extra']['glueful']['version'] ?? null) : null;
            self::$cachedVersion = is_string($version) ? $version : '0.0.0';
        }

        return self::$cachedVersion;
    }

    /**
     * Service definitions for DI compilation.
     *
     * @return array<string,mixed>
     */
    public static function services(): array
    {
        return [
            AuditRecorder::class => self::autowired(
                AuditRecorder::class,
                aliases: [AuditRecorderInterface::class]
            ),
            ActorResolver::class => self::autowired(ActorResolver::class),
            AuditSubscriber::class => self::autowired(AuditSubscriber::class),
            AegisAuditSubscriber::class => self::autowired(AegisAuditSubscriber::class),
            AuditLogRepository::class => self::autowired(AuditLogRepository::class),
            AuditLogController::class => self::autowired(AuditLogController::class),
            PruneAuditLogsCommand::class => self::autowired(PruneAuditLogsCommand::class),
            RequireAuditPermission::class => self::autowired(
                RequireAuditPermission::class,
                aliases: ['audit_permission']
            ),
        ];
    }

    /**
     * @param class-string $class
     * @param list<string> $aliases
     * @return array{class:class-string,shared:bool,autowire:bool,alias?:list<string>}
     */
    private static function autowired(string $class, bool $shared = true, array $aliases = []): array
    {
        $definition = ['class' => $class, 'shared' => $shared, 'autowire' => true];
        if ($aliases !== []) {
            $definition['alias'] = $aliases;
        }

        return $definition;
    }

    public function getName(): string
    {
        return 'Audit';
    }

    public function getVersion(): string
    {
        return self::composerVersion();
    }

    public function getDescription(): string
    {
        return 'Event-sourced audit trail for Glueful apps.';
    }

    public function register(ApplicationContext $context): void
    {
        $this->mergeConfig('audit', require __DIR__ . '/../config/audit.php');
    }

    public function boot(ApplicationContext $context): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../migrations', MigrationPriority::DEFAULT, 'glueful/audit');

        if ((bool) config($context, 'audit.enabled', true)) {
            // Is RBAC captured semantically? (Aegis events present AND capture.rbac on.) The generic
            // subscriber reads audit.rbac_semantic_active to decide pivot suppression vs. fallback; it
            // also gates the Aegis subscriber. config() is read-only in this framework, so the flag is
            // SET via ApplicationContext::mergeConfigDefaults() (the same mechanism mergeConfig uses) —
            // it merges UNDER any config file but this key lives nowhere on disk, so config() returns it.
            $rbacSemantic = (bool) config($context, 'audit.capture.rbac', true)
                && class_exists(\Glueful\Extensions\Aegis\Events\RoleAssignedEvent::class);
            $context->mergeConfigDefaults('audit', ['rbac_semantic_active' => $rbacSemantic]);

            $events = app($context, EventService::class);
            $events->subscribe(AuditSubscriber::class);          // suppresses pivots iff rbac_semantic_active
            if ($rbacSemantic) {
                $events->subscribe(AegisAuditSubscriber::class); // semantic RBAC rows
            }
        }

        if ((bool) config($context, 'audit.routes_enabled', true)) {
            $this->loadRoutesFrom(__DIR__ . '/../routes/routes.php');
        }

        $this->discoverCommands('Glueful\\Extensions\\Audit\\Console', __DIR__ . '/Console');
    }

    /**
     * @return list<Permission>
     */
    public function permissions(): array
    {
        return [
            Permission::define('audit.view')
                ->label('View audit log')
                ->category('Audit')
                ->resource('audit')
                ->managedBy('glueful/audit'),
        ];
    }
}
