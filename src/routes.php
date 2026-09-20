<?php

declare(strict_types=1);

use Naf\Rbac\Http\GrantController;
use Naf\Rbac\Http\RoleController;

use function Naf\config;
use function Naf\route;

/*
 * Two endpoints and nothing else.
 *
 * There is no page here on purpose: a host that installs this package already
 * has a place where settings live, and the shipped view is a fragment it drops
 * in. What a package cannot bring with it is a shell -- its own navigation and
 * heading inside somebody else's application is exactly the seam that makes an
 * embedded screen look embedded.
 *
 * Set rbac:path to null to register nothing at all and call the services from
 * screens of your own.
 */
$path = config('rbac:path', '/admin/roles');

if (!is_string($path) || $path === '') {
    return;
}

route()->add('POST', $path, [RoleController::class, 'save'], 'rbac.roles.save');
route()->add('POST', $path . '/delete', [RoleController::class, 'delete'], 'rbac.roles.delete');
route()->add('POST', $path . '/grants', [GrantController::class, 'save'], 'rbac.grants.save');
