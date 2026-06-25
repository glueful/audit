<?php

declare(strict_types=1);

use Glueful\Extensions\Audit\Http\Controllers\AuditLogController;
use Glueful\Routing\Router;

/** @var Router $router Router instance injected by RouteManifest::load() */

$router->group(['prefix' => '/audit-logs', 'middleware' => ['auth']], function (Router $router): void {
    $router->get('', [AuditLogController::class, 'index'])->middleware('audit_permission:audit.view');
    $router->get('/{uuid}', [AuditLogController::class, 'show'])->middleware('audit_permission:audit.view');
});
